package main

import (
	"encoding/binary"

	"io"
	"net"

	log "github.com/sirupsen/logrus"
	msgpack "github.com/vmihailenco/msgpack"
)

func SendMessage(conn net.Conn, msg interface{}) error {
	data, err := msgpack.Marshal(msg)
	if err != nil {
		return err
	}

	var datalen int32 = int32(len(data))

	err = binary.Write(conn, binary.BigEndian, datalen)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)

	return err
}

func RecvMessage(conn net.Conn, msg interface{}) error {
	var datalen uint32

	log.Debug("READ LEN")

	err := binary.Read(conn, binary.BigEndian, &datalen)
	if err != nil {
		log.Debug("READ LEN FAILED: ", err)
		return err
	}

	log.Debug("READ LEN:", datalen)
	data := make([]byte, datalen)

	_, err = io.ReadFull(conn, data)
	if err != nil {
		return err
	}

	log.Debug("UNMARSHAL:", data)
	return msgpack.Unmarshal(data, msg)
}
