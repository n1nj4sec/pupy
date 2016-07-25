"""
The scramblesuit module implements the ScrambleSuit obfuscation protocol.

The paper discussing the design and evaluation of the ScrambleSuit pluggable
transport protocol is available here:
http://www.cs.kau.se/philwint/scramblesuit/
"""

#from twisted.internet import reactor
from ..obfscommon import threads as reactor

from ... import base
import logging

import random
import base64
import yaml
import argparse

import probdist
import mycrypto
import message
import const
import util
import packetmorpher
import ticket
import uniformdh
import state
import fifobuf


log = logging

class ReadPassFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        with open(values) as f:
            setattr(namespace, self.dest, f.readline().strip())


class ScrambleSuitTransport( base.BaseTransport ):

    """
    Implement the ScrambleSuit protocol.

    The class implements methods which implement the ScrambleSuit protocol.  A
    large part of the protocol's functionality is outsources to different
    modules.
    """

    def __init__( self, *args, **kwargs):
        """
        Initialise a ScrambleSuitTransport object.
        """

        #log.debug("Initialising %s." % const.TRANSPORT_NAME)

        super(ScrambleSuitTransport, self).__init__(*args, **kwargs)

        # Load the server's persistent state from file.
        if self.weAreServer:
            self.srvState = state.load()

        # Initialise the protocol's state machine.
        #log.debug("Switching to state ST_WAIT_FOR_AUTH.")
        self.protoState = const.ST_WAIT_FOR_AUTH

        # Buffer for outgoing data.
        self.sendBuf = ""

        # Buffer for inter-arrival time obfuscation.
        self.choppingBuf = fifobuf.Buffer()

        # AES instances to decrypt incoming and encrypt outgoing data.
        self.sendCrypter = mycrypto.PayloadCrypter()
        self.recvCrypter = mycrypto.PayloadCrypter()

        # Packet morpher to modify the protocol's packet length distribution.
        self.pktMorpher = packetmorpher.new(self.srvState.pktDist
                                            if self.weAreServer else None)

        # Inter-arrival time morpher to obfuscate inter arrival times.
        self.iatMorpher = self.srvState.iatDist if self.weAreServer else \
                          probdist.new(lambda: random.random() %
                                       const.MAX_PACKET_DELAY)

        # Used to extract protocol messages from encrypted data.
        self.protoMsg = message.MessageExtractor()

        # Used by the server-side: `True' if the ticket is already
        # decrypted but not yet authenticated.
        self.decryptedTicket = False

        # If we are in external mode we should already have a shared
        # secret set up because of validate_external_mode_cli().
        if self.weAreExternal:
            assert(self.uniformDHSecret)

        if self.weAreClient and not self.weAreExternal:
            # As a client in managed mode, we get the shared secret
            # from callback `handle_socks_args()' per-connection. Set
            # the shared secret to None for now.
            self.uniformDHSecret = None

        self.uniformdh = uniformdh.new(self.uniformDHSecret, self.weAreServer)

    @classmethod
    def setup( cls, transportConfig ):
        """
        Called once when obfsproxy starts.
        """

        #log.error("\n\n################################################\n"
        #          "Do NOT rely on ScrambleSuit for strong security!\n"
        #          "################################################\n")

        util.setStateLocation(transportConfig.getStateLocation())

        cls.weAreClient = transportConfig.weAreClient
        cls.weAreServer = not cls.weAreClient
        cls.weAreExternal = transportConfig.weAreExternal

        # If we are server and in managed mode, we should get the
        # shared secret from the server transport options.
        if cls.weAreServer and not cls.weAreExternal:
            cfg  = transportConfig.getServerTransportOptions()
            if cfg and "password" in cfg:
                try:
                    cls.uniformDHSecret = base64.b32decode(util.sanitiseBase32(
                        cfg["password"]))
                except (TypeError, AttributeError) as error:
                    raise base.TransportSetupFailed(
                        "Password could not be base32 decoded (%s)" % error)

                cls.uniformDHSecret = cls.uniformDHSecret.strip()

        if cls.weAreServer:
            if not hasattr(cls, "uniformDHSecret"):
                #log.debug("Using fallback password for descriptor file.")
                srv = state.load()
                cls.uniformDHSecret = srv.fallbackPassword

            if len(cls.uniformDHSecret) != const.SHARED_SECRET_LENGTH:
                raise base.TransportSetupFailed(
                    "Wrong password length (%d instead of %d)"
                    % len(cls.uniformDHSecret), const.SHARED_SECRET_LENGTH)

            if not const.STATE_LOCATION:
                raise base.TransportSetupFailed(
                    "No state location set. If you are using external mode, " \
                    "please set it using the --data-dir switch.")

            state.writeServerPassword(cls.uniformDHSecret)

    @classmethod
    def get_public_server_options( cls, transportOptions ):
        """
        Return ScrambleSuit's BridgeDB parameters, i.e., the shared secret.

        As a fallback mechanism, we return an automatically generated password
        if the bridge operator did not use `ServerTransportOptions'.
        """

        #log.debug("Tor's transport options: %s" % str(transportOptions))

        if not "password" in transportOptions:
            #log.warning("No password found in transport options (use Tor's " \
            #            "`ServerTransportOptions' to set your own password)." \
            #            "  Using automatically generated password instead.")
            srv = state.load()
            transportOptions = {"password":
                                base64.b32encode(srv.fallbackPassword)}
            cls.uniformDHSecret = srv.fallbackPassword

        return transportOptions

    def deriveSecrets( self, masterKey ):
        """
        Derive various session keys from the given `masterKey'.

        The argument `masterKey' is used to derive two session keys and nonces
        for AES-CTR and two HMAC keys.  The derivation is done using
        HKDF-SHA256.
        """

        assert len(masterKey) == const.MASTER_KEY_LENGTH

        #log.debug("Deriving session keys from %d-byte master key." %
        #          len(masterKey))

        # We need key material for two symmetric AES-CTR keys, nonces and
        # HMACs.  In total, this equals 144 bytes of key material.
        hkdf = mycrypto.HKDF_SHA256(masterKey, "", (32 * 4) + (8 * 2))
        okm = hkdf.expand()
        assert len(okm) >= ((32 * 4) + (8 * 2))

        # Set AES-CTR keys and nonces for our two AES instances.
        self.sendCrypter.setSessionKey(okm[0:32],  okm[32:40])
        self.recvCrypter.setSessionKey(okm[40:72], okm[72:80])

        # Set the keys for the two HMACs protecting our data integrity.
        self.sendHMAC = okm[80:112]
        self.recvHMAC = okm[112:144]

        if self.weAreServer:
            self.sendHMAC, self.recvHMAC = self.recvHMAC, self.sendHMAC
            self.sendCrypter, self.recvCrypter = self.recvCrypter, \
                                                 self.sendCrypter

    def circuitConnected( self ):
        """
        Initiate a ScrambleSuit handshake.

        This method is only relevant for clients since servers never initiate
        handshakes.  If a session ticket is available, it is redeemed.
        Otherwise, a UniformDH handshake is conducted.
        """

        # The server handles the handshake passively.
        if self.weAreServer:
            return

        # The preferred authentication mechanism is a session ticket.
        bridge = self.circuit.downstream.transport.getPeer()
        storedTicket = ticket.findStoredTicket(bridge)

        if storedTicket is not None:
            #log.debug("Redeeming stored session ticket.")
            (masterKey, rawTicket) = storedTicket
            self.deriveSecrets(masterKey)
            self.circuit.downstream.write(ticket.createTicketMessage(rawTicket,
                                                                self.sendHMAC))

            # We switch to ST_CONNECTED opportunistically since we don't know
            # yet whether the server accepted the ticket.
            #log.debug("Switching to state ST_CONNECTED.")
            self.protoState = const.ST_CONNECTED

            self.flushSendBuffer()

        # Conduct an authenticated UniformDH handshake if there's no ticket.
        else:
            if self.uniformDHSecret is None:
                #log.warning("A UniformDH password is not set, most likely " \
                #            "a missing 'password' argument.")
                self.circuit.close()
                return
            #log.debug("No session ticket to redeem.  Running UniformDH.")
            self.circuit.downstream.write(self.uniformdh.createHandshake())

    def sendRemote( self, data, flags=const.FLAG_PAYLOAD ):
        """
        Send data to the remote end after a connection was established.

        The given `data' is first encapsulated in protocol messages.  Then, the
        protocol message(s) are sent over the wire.  The argument `flags'
        specifies the protocol message flags with the default flags signalling
        payload.
        """

        #log.debug("Processing %d bytes of outgoing data." % len(data))

        # Wrap the application's data in ScrambleSuit protocol messages.
        messages = message.createProtocolMessages(data, flags=flags)
        blurb = "".join([msg.encryptAndHMAC(self.sendCrypter,
                        self.sendHMAC) for msg in messages])

        # Flush data chunk for chunk to obfuscate inter-arrival times.
        if const.USE_IAT_OBFUSCATION:

            if len(self.choppingBuf) == 0:
                self.choppingBuf.write(blurb)
                reactor.callLater(self.iatMorpher.randomSample(),
                                  self.flushPieces)
            else:
                # flushPieces() is still busy processing the chopping buffer.
                self.choppingBuf.write(blurb)

        else:
            padBlurb = self.pktMorpher.getPadding(self.sendCrypter,
                                                  self.sendHMAC,
                                                  len(blurb))
            self.circuit.downstream.write(blurb + padBlurb)

    def flushPieces( self ):
        """
        Write the application data in chunks to the wire.

        The cached data is sent over the wire in chunks.  After every write
        call, control is given back to the Twisted reactor so it has a chance
        to flush the data.  Shortly thereafter, this function is called again
        to write the next chunk of data.  The delays in between subsequent
        write calls are controlled by the inter-arrival time obfuscator.
        """

        # Drain and send an MTU-sized chunk from the chopping buffer.
        if len(self.choppingBuf) > const.MTU:

            self.circuit.downstream.write(self.choppingBuf.read(const.MTU))

        # Drain and send whatever is left in the output buffer.
        else:
            blurb = self.choppingBuf.read()
            padBlurb = self.pktMorpher.getPadding(self.sendCrypter,
                                                  self.sendHMAC,
                                                  len(blurb))
            self.circuit.downstream.write(blurb + padBlurb)
            return

        reactor.callLater(self.iatMorpher.randomSample(), self.flushPieces)

    def processMessages( self, data ):
        """
        Acts on extracted protocol messages based on header flags.

        After the incoming `data' is decrypted and authenticated, this method
        processes the received data based on the header flags.  Payload is
        written to the local application, new tickets are stored, or keys are
        added to the replay table.
        """

        if (data is None) or (len(data) == 0):
            return

        # Try to extract protocol messages from the encrypted blurb.
        msgs  = self.protoMsg.extract(data, self.recvCrypter, self.recvHMAC)
        if (msgs is None) or (len(msgs) == 0):
            return

        for msg in msgs:
            # Forward data to the application.
            if msg.flags == const.FLAG_PAYLOAD:
                self.circuit.upstream.write(msg.payload)

            # Store newly received ticket.
            elif self.weAreClient and (msg.flags == const.FLAG_NEW_TICKET):
                assert len(msg.payload) == (const.TICKET_LENGTH +
                                            const.MASTER_KEY_LENGTH)
                peer = self.circuit.downstream.transport.getPeer()
                ticket.storeNewTicket(msg.payload[0:const.MASTER_KEY_LENGTH],
                                      msg.payload[const.MASTER_KEY_LENGTH:
                                                  const.MASTER_KEY_LENGTH +
                                                  const.TICKET_LENGTH], peer)

            # Use the PRNG seed to generate the same probability distributions
            # as the server.  That's where the polymorphism comes from.
            elif self.weAreClient and (msg.flags == const.FLAG_PRNG_SEED):
                assert len(msg.payload) == const.PRNG_SEED_LENGTH
                #log.debug("Obtained PRNG seed.")
                prng = random.Random(msg.payload)
                pktDist = probdist.new(lambda: prng.randint(const.HDR_LENGTH,
                                                            const.MTU),
                                       seed=msg.payload)
                self.pktMorpher = packetmorpher.new(pktDist)
                self.iatMorpher = probdist.new(lambda: prng.random() %
                                               const.MAX_PACKET_DELAY,
                                               seed=msg.payload)

            else:
                #log.warning("Invalid message flags: %d." % msg.flags)
                pass

    def flushSendBuffer( self ):
        """
        Flush the application's queued data.

        The application could have sent data while we were busy authenticating
        the remote machine.  This method flushes the data which could have been
        queued in the meanwhile in `self.sendBuf'.
        """

        if len(self.sendBuf) == 0:
            #log.debug("Send buffer is empty; nothing to flush.")
            return

        # Flush the buffered data, the application is so eager to send.
        #log.debug("Flushing %d bytes of buffered application data." %
        #          len(self.sendBuf))

        self.sendRemote(self.sendBuf)
        self.sendBuf = ""

    def receiveTicket( self, data ):
        """
        Extract and verify a potential session ticket.

        The given `data' is treated as a session ticket.  The ticket is being
        decrypted and authenticated (yes, in that order).  If all these steps
        succeed, `True' is returned.  Otherwise, `False' is returned.
        """

        if len(data) < (const.TICKET_LENGTH + const.MARK_LENGTH +
                        const.HMAC_SHA256_128_LENGTH):
            return False

        potentialTicket = data.peek()

        # Now try to decrypt and parse the ticket.  We need the master key
        # inside to verify the HMAC in the next step.
        if not self.decryptedTicket:
            newTicket = ticket.decrypt(potentialTicket[:const.TICKET_LENGTH],
                                       self.srvState)
            if newTicket != None and newTicket.isValid():
                self.deriveSecrets(newTicket.masterKey)
                self.decryptedTicket = True
            else:
                return False

        # First, find the mark to efficiently locate the HMAC.
        mark = mycrypto.HMAC_SHA256_128(self.recvHMAC,
                                        potentialTicket[:const.TICKET_LENGTH])

        index = util.locateMark(mark, potentialTicket)
        if not index:
            return False

        # Now, verify if the HMAC is valid.
        existingHMAC = potentialTicket[index + const.MARK_LENGTH:
                                       index + const.MARK_LENGTH +
                                       const.HMAC_SHA256_128_LENGTH]
        authenticated = False
        for epoch in util.expandedEpoch():
            myHMAC = mycrypto.HMAC_SHA256_128(self.recvHMAC,
                                              potentialTicket[0:index + \
                                              const.MARK_LENGTH] + epoch)

            if util.isValidHMAC(myHMAC, existingHMAC, self.recvHMAC):
                authenticated = True
                break

            #log.debug("HMAC invalid.  Trying next epoch value.")

        if not authenticated:
            #log.warning("Could not verify the authentication message's HMAC.")
            return False

        # Do nothing if the ticket is replayed.  Immediately closing the
        # connection would be suspicious.
        if self.srvState.isReplayed(existingHMAC):
            #log.warning("The HMAC was already present in the replay table.")
            return False

        data.drain(index + const.MARK_LENGTH + const.HMAC_SHA256_128_LENGTH)

        #log.debug("Adding the HMAC authenticating the ticket message to the " \
        #          "replay table: %s." % existingHMAC.encode('hex'))
        self.srvState.registerKey(existingHMAC)

        #log.debug("Switching to state ST_CONNECTED.")
        self.protoState = const.ST_CONNECTED

        return True

    def receivedUpstream( self, data ):
        """
        Sends data to the remote machine or queues it to be sent later.

        Depending on the current protocol state, the given `data' is either
        directly sent to the remote machine or queued.  The buffer is then
        flushed once, a connection is established.
        """

        if self.protoState == const.ST_CONNECTED:
            self.sendRemote(data.read())

        # Buffer data we are not ready to transmit yet.
        else:
            self.sendBuf += data.read()
            #log.debug("Buffered %d bytes of outgoing data." %
            #          len(self.sendBuf))

    def sendTicketAndSeed( self ):
        """
        Send a session ticket and the PRNG seed to the client.

        This method is only called by the server after successful
        authentication.  Finally, the server's send buffer is flushed.
        """

        #log.debug("Sending a new session ticket and the PRNG seed to the " \
        #          "client.")

        self.sendRemote(ticket.issueTicketAndKey(self.srvState),
                        flags=const.FLAG_NEW_TICKET)
        self.sendRemote(self.srvState.prngSeed,
                        flags=const.FLAG_PRNG_SEED)
        self.flushSendBuffer()

    def receivedDownstream( self, data ):
        """
        Receives and processes data coming from the remote machine.

        The incoming `data' is dispatched depending on the current protocol
        state and whether we are the client or the server.  The data is either
        payload or authentication data.
        """

        if self.weAreServer and (self.protoState == const.ST_AUTH_FAILED):

            self.drainedHandshake += len(data)
            data.drain(len(data))

            if self.drainedHandshake > self.srvState.closingThreshold:
                #log.info("Terminating connection after having received >= %d"
                #         " bytes because client could not "
                #         "authenticate." % self.srvState.closingThreshold)
                self.circuit.close()
                return

        elif self.weAreServer and (self.protoState == const.ST_WAIT_FOR_AUTH):

            # First, try to interpret the incoming data as session ticket.
            if self.receiveTicket(data):
                #log.debug("Ticket authentication succeeded.")

                self.sendTicketAndSeed()

            # Second, interpret the data as a UniformDH handshake.
            elif self.uniformdh.receivePublicKey(data, self.deriveSecrets,
                    self.srvState):
                # Now send the server's UniformDH public key to the client.
                handshakeMsg = self.uniformdh.createHandshake(srvState=
                                                              self.srvState)

                #log.debug("Sending %d bytes of UniformDH handshake and "
                #          "session ticket." % len(handshakeMsg))

                self.circuit.downstream.write(handshakeMsg)
                #log.debug("UniformDH authentication succeeded.")

                #log.debug("Switching to state ST_CONNECTED.")
                self.protoState = const.ST_CONNECTED

                self.sendTicketAndSeed()

            elif len(data) > const.MAX_HANDSHAKE_LENGTH:
                self.protoState = const.ST_AUTH_FAILED
                self.drainedHandshake = len(data)
                data.drain(self.drainedHandshake)
                #log.info("No successful authentication after having " \
                #         "received >= %d bytes.  Now ignoring client." % \
                #         const.MAX_HANDSHAKE_LENGTH)
                return

            else:
                #log.debug("Authentication unsuccessful so far.  "
                #          "Waiting for more data.")
                return

        elif self.weAreClient and (self.protoState == const.ST_WAIT_FOR_AUTH):

            if not self.uniformdh.receivePublicKey(data, self.deriveSecrets):
                #log.debug("Unable to finish UniformDH handshake just yet.")
                return

            #log.debug("UniformDH authentication succeeded.")

            #log.debug("Switching to state ST_CONNECTED.")
            self.protoState = const.ST_CONNECTED
            self.flushSendBuffer()

        if self.protoState == const.ST_CONNECTED:

            self.processMessages(data.read())

    @classmethod
    def register_external_mode_cli( cls, subparser ):
        """
        Register a CLI arguments to pass a secret or ticket to ScrambleSuit.

        Two options are made available over the command line interface: one to
        specify a ticket file and one to specify a UniformDH shared secret.
        """

        passArgs = subparser.add_mutually_exclusive_group(required=True)

        passArgs.add_argument("--password",
                               type=str,
                               help="Shared secret for UniformDH",
                               dest="uniformDHSecret")

        passArgs.add_argument("--password-file",
                               type=str,
                               help="File containing shared secret for UniformDH",
                               action=ReadPassFile,
                               dest="uniformDHSecret")

        super(ScrambleSuitTransport, cls).register_external_mode_cli(subparser)

    @classmethod
    def validate_external_mode_cli( cls, args ):
        """
        Assign the given command line arguments to local variables.
        """

        uniformDHSecret = None

        try:
            uniformDHSecret = base64.b32decode(util.sanitiseBase32(
                                     args.uniformDHSecret))
        except (TypeError, AttributeError) as error:
            log.error(error.message)
            raise base.PluggableTransportError("Given password '%s' is not " \
                    "valid Base32!  Run 'generate_password.py' to generate " \
                    "a good password." % args.uniformDHSecret)

        parentalApproval = super(
            ScrambleSuitTransport, cls).validate_external_mode_cli(args)
        if not parentalApproval:
            # XXX not very descriptive nor helpful, but the parent class only
            #     returns a boolean without telling us what's wrong.
            raise base.PluggableTransportError(
                "Pluggable Transport args invalid: %s" % args )

        if uniformDHSecret:
            rawLength = len(uniformDHSecret)
            if rawLength != const.SHARED_SECRET_LENGTH:
                raise base.PluggableTransportError(
                    "The UniformDH password must be %d bytes in length, ",
                    "but %d bytes are given."
                    % (const.SHARED_SECRET_LENGTH, rawLength))
            else:
                cls.uniformDHSecret = uniformDHSecret

    def handle_socks_args( self, args ):
        """
        Receive arguments `args' passed over a SOCKS connection.

        The SOCKS authentication mechanism is (ab)used to pass arguments to
        pluggable transports.  This method receives these arguments and parses
        them.  As argument, we only expect a UniformDH shared secret.
        """

        #log.debug("Received the following arguments over SOCKS: %s." % args)

        if len(args) != 1:
            raise base.SOCKSArgsError("Too many SOCKS arguments "
                                      "(expected 1 but got %d)." % len(args))

        # The ScrambleSuit specification defines that the shared secret is
        # called "password".
        if not args[0].startswith("password="):
            raise base.SOCKSArgsError("The SOCKS argument must start with "
                                      "`password='.")

        # A shared secret might already be set if obfsproxy is in external
        # mode.
        if self.uniformDHSecret:
            log.warning("A UniformDH password was already specified over "
                        "the command line.  Using the SOCKS secret instead.")

        try:
            self.uniformDHSecret = base64.b32decode(util.sanitiseBase32(
                                          args[0].split('=')[1].strip()))
        except TypeError as error:
            log.error(error.message)
            raise base.PluggableTransportError("Given password '%s' is not " \
                    "valid Base32!  Run 'generate_password.py' to generate " \
                    "a good password." % args[0].split('=')[1].strip())

        rawLength = len(self.uniformDHSecret)
        if rawLength != const.SHARED_SECRET_LENGTH:
            raise base.PluggableTransportError("The UniformDH password "
                    "must be %d bytes in length but %d bytes are given." %
                    (const.SHARED_SECRET_LENGTH, rawLength))

        self.uniformdh = uniformdh.new(self.uniformDHSecret, self.weAreServer)


class ScrambleSuitClient( ScrambleSuitTransport ):

    """
    Extend the ScrambleSuit class.
    """

    password=None
    def __init__( self, *args, **kwargs ):
        """
        Initialise a ScrambleSuitClient object.
        """

        self.weAreServer=False
        self.weAreClient=True
        self.weAreExternal=True
        if 'password' in kwargs:
            self.password=kwargs['password']
        uniformDHSecret = self.password
        rawLength = len(uniformDHSecret)
        if rawLength != const.SHARED_SECRET_LENGTH:
            raise base.PluggableTransportError(
                "The UniformDH password must be %d bytes in length, but %d bytes are given."
                % (const.SHARED_SECRET_LENGTH, rawLength))
        else:
            self.uniformDHSecret = uniformDHSecret
        ScrambleSuitTransport.__init__(self, *args, **kwargs)


class ScrambleSuitServer( ScrambleSuitTransport ):

    """
    Extend the ScrambleSuit class.
    """
    password=None
    def __init__( self, *args, **kwargs ):
        """
        Initialise a ScrambleSuitServer object.
        """
        
        self.weAreServer=True
        self.weAreClient=False
        self.weAreExternal=True
        if 'password' in kwargs:
            self.password=kwargs['password']
        uniformDHSecret = self.password
        rawLength = len(uniformDHSecret)
        if rawLength != const.SHARED_SECRET_LENGTH:
            raise base.PluggableTransportError(
                "The UniformDH password must be %d bytes in length, but %d bytes are given."
                % (const.SHARED_SECRET_LENGTH, rawLength))
        else:
            self.uniformDHSecret = uniformDHSecret
        ScrambleSuitTransport.__init__(self, *args, **kwargs)
