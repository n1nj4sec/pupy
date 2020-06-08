# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

__all__ = (
    'DnsEncoder', 'Huffman'
)

from io import open

IS_END = '\0'

FREEDNS = (
    '100mountain.com', '10x.es', '120v.ac', '1337.cx', '24-7.ro',
    '2fine.de', '2p.fm', '3dxtras.com', '3trust.com', '404.mn', '4040.idv.tw',
    '4twenty.us', '688.org', '69.mu', 'abuser.eu', 'agropeople.ru', 'aintno.info',
    'allisons.org', 'allowed.org', 'americajhon.com.pe', 'ananda.net.ve',
    'antongorbunov.com', 'asenov.ru', 'asianfreshproduce.com', 'ask2ask.com',
    'astrabus.ru', 'auraria.org', 'australia.ai', 'awiki.org', 'b33r.us', 'bad.mn',
    'bandweite.de', 'beerprojects.com', 'benjamin.it', 'bigbox.info',
    'birdriver.org', 'biz.tm', 'blinklab.com', 'blizzie.net', 'bloom.us', 'bot.nu',
    'boxathome.net', 'ccmissoula.com', 'celebsplay.com', 'chickenkiller.com',
    'cloudwatch.net', 'cnstefancelmare.ro', 'computersforpeace.net',
    'crabdance.com', 'crackedsidewalks.com', 'crazycat.ro', 'csproject.org',
    'custom-gaming.net', 'd-n-s.name', 'd-n-s.org.uk', 'dalk.ru', 'darksair.org',
    'digitalgroupe.com', 'dmtr.ru', 'dnet.hu', 'dob.jp', 'dp76.com',
    'drunkensailor.org', 'dyn.mk', 'e-data.com.tr', 'e-m-a-i-l.org', 'elchemi.com',
    'endlessmovie.com', 'enemyterritory.org', 'epicgamer.org', 'erke.biz.tr',
    'erki.net', 'eva.hk', 'everton.com', 'evils.in', 'evs.net.br', 'ezxdev.org',
    'fairuse.org', 'farted.net', 'fedea.com.ar', 'fin-tech.com', 'fivepals.com',
    'forss.to', 'fr.to', 'ftp.sh', 'galipan.net.ve', 'gerastar.ru',
    'ghostnation.org', 'giveawaylisting.com', 'good-newz.org', 'good.one.pl',
    'gtk.cl', 'gurcanozturk.com', 'h-o-s-t.name', 'h0stname.net', 'h4ck.me',
    'hackquest.com', 'hamshack.info', 'happyforever.com', 'hbmc.net',
    'hiddencorner.org', 'hijaxdesigns.com', 'hin.tw', 'hitremixes.com', 'hmail.us',
    'hmao.pro', 'home.kg', 'homelinuxserver.org', 'homeplex.org', 'host2go.net',
    'hpc.tw', 'hs.vc', 'iceblaze.com', 'ig42.org', 'ignorelist.com', 'iiiii.info',
    'iminecraft.se', 'inet2.org', 'inflict.us', 'info.gf', 'info.tm',
    'innograph.co.id', 'inovasi.co.id', 'iu4ever.org', 'ivi.pl', 'jedimasters.net',
    'jesus.si', 'joe.dj', 'joiavip.com.br', 'jumpingcrab.com', 'jundy.org',
    'k22.su', 'kalbas.com.vn', 'kck-saratov.ru', 'kein.hk', 'kir22.ru', 'ko.tl',
    'kyrgyzstan.kg', 'l5.ca', 'lanas.cl', 'lee.mx', 'lex.mn', 'linkin.tw',
    'lovethosetrains.com', 'madhacker.biz', 'make.com.ar', 'malam.or.id',
    'mcsoft.org', 'mikata.ru', 'mindhackers.org', 'mine.bz', 'minecraftnoob.com',
    'minecraftr.us', 'mm.my', 'mooo.com', 'mooo.info', 'morganisageek.org',
    'mwop.net', 'my.to', 'mycloud.bz', 'mylogisoft.com', 'mysaol.com',
    'n-e-t.name', 'nard.ca', 'nav.co.id', 'nedvighimost-sochi.ru', 'netlord.de',
    'notici.as', 'now.im', 'oganilirkab.go.id', 'ohbah.com', 'patelmortgage.com',
    'photo-cult.com', 'photo-frame.com', 'php-dev.net', 'pii.at',
    'pixelfucker.com', 'playminecraft.ml', 'polissya.eu', 'port0.org',
    'portalindustries.org', 'possessed.us', 'priamaakcia.sk', 'privatedns.org',
    'privateimport.jp', 'procare.co.id', 'prostore.ru', 'psybnc.org', 'punked.us',
    'qc.to', 'qlbv.vn', 'r-o-o-t.net', 'radiogirl.fm', 'raspberryip.com',
    'reason.org.nz', 'richlorenz.com', 'ro.lt', 'root.sx', 'routemehome.com',
    'ruok.org', 'rwbcode.com', 'sadayuki.jp', 'sales-people.ru', 'scay.net',
    'scottlewisonline.com', 'sdp-mos.ru', 'servernux.com', 'serverpit.com',
    'shen.cl', 'shop.tm', 'sly.io', 'smelly.cc', 'soon.it', 'spacetechnology.net',
    'spelar.se', 'stfu-kthx.net', 'stocktester.ru', 'strangled.net',
    'stroyexpert.org', 'suka.se', 'sumibi.org', 'surak.kz', 'surfnet.ca',
    't28.net', 'takeshi.cnt.br', 'technopagans.com', 'thehomeserver.net', 'tru.io',
    'tuck.tw', 'twilightparadox.com', 'tzafrir.org.il', 'u888.cn', 'ufodns.com',
    'ugo.si', 'uk.ms', 'uk.to', 'undo.it', 'us.to', 'vankin.de', 'vctel.com',
    've3.info', 'verymad.net', 'violates.me', 'vxe6.net', 'webs.vc', 'wiki.gd',
    'wildsurf.net', 'winkel.com.ar', 'womenclothingtoday.com', 'xpresit.net',
    'xxxxx.tw', 'yngling.com', 'yourspecialtee.com', 'z0d.eu', 'z86.ru',
    'zanity.net'
)

DNS_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789-.'

class Node(object):
    __slots__ = (
        'weight', 'value'
    )

    def __init__(self, value, weight):
        self.weight = weight
        self.value = value

    def __lt__(self, other):
        if hasattr(other, 'value'):
            if self.value == IS_END:
                return False

        return self.weight < other.weight

    def __repr__(self):
        return '{{N:{}({})}}'.format(self.weight, self.value)


class Root(object):
    __slots__ = (
        'weight', 'A', 'B'
    )

    def __init__(self, A=None, B=None):
        self.weight = 0
        if A is not None:
            self.weight += A.weight
            self.A = A

        if B is not None:
            self.weight += B.weight
            self.B = B

    def __lt__(self, other):
        return self.weight < other.weight

    def __repr__(self):
        return '{{R:{}}}'.format(self.weight, self.A, self.B)


class Huffman(object):
    __slots__ = (
        'encoding_table', 'decoding_tree', 'decoding_table',
    )

    def __init__(self, decoding_tree=None, decoding_table=None):
        self.encoding_table = None
        self.decoding_table = []
        self.decoding_tree = decoding_tree

        if self.decoding_tree:
            self._generate_table()

        if decoding_table:
            self.set_decoding_table(decoding_table)

    def set_decoding_table(self, decoding_table):
        self.decoding_table = decoding_table
        self.encoding_table = tuple(
            (term, value, bitlen) for value, bitlen, term in sorted(
                self.decoding_table, key=lambda x: len(x[2]), reverse=True
            )
        )

    def _generate_table(self):
        self.encoding_table = {}

        def bitlen(x):
            i = 0
            while x:
                x >>= 1
                i += 1
            return i - 1

        def _walk(tree, prefix=1):
            if type(tree) == tuple:
                _walk(tree[0], (prefix << 1) | 0)
                _walk(tree[1], (prefix << 1) | 1)
            else:
                b = bitlen(prefix)
                prefix &= ((1 << b) - 1)
                self.encoding_table[tree] = (prefix, b)
                self.decoding_table.append((prefix, b, tree))

        _walk(self.decoding_tree)

        self.decoding_table = sorted(self.decoding_table, key=lambda x: x[1], reverse=True)
        self.encoding_table = tuple(
            (
                term,
                self.encoding_table[term][0],
                self.encoding_table[term][1]
            ) for term in sorted(
                self.encoding_table,
                # key=lambda x: len(self.encoding_table[x]),
                key=lambda x: self.encoding_table[x][1],
                reverse=True
            )
        )

    def encode(self, phrase, last=False):
        phrase += '\x00'

        encoded = []
        remainder = 0
        remainder_bits = 8

        min_bits = min(
            bitlen for _, _, bitlen in self.encoding_table
        )

        while phrase:
            found = False

            if last and phrase.startswith('\x00') and remainder_bits < min_bits:
                break

            for term, value, bitlen in self.encoding_table:
                if phrase.startswith(term):
                    found = True

                    while bitlen:
                        consume_bits = min(bitlen, remainder_bits)
                        rest_bits = bitlen - consume_bits

                        remainder <<= consume_bits
                        remainder |= (value >> rest_bits)

                        value &= ((1 << rest_bits) - 1)
                        bitlen -= consume_bits
                        remainder_bits -= consume_bits

                        if remainder_bits == 0:
                            encoded.append(remainder)
                            remainder = 0
                            remainder_bits = 8

                    phrase = phrase[len(term):]
                    break

            if not found:
                raise ValueError('Not found beginning for ', phrase)

        if remainder_bits:
            remainder <<= remainder_bits
            encoded.append(remainder)

        return ''.join(chr(x) for x in encoded)

    def decode(self, values):
        if not values:
            return

        decoded = []

        max_bitlen = max(
            bitlen for _, bitlen, _ in self.decoding_table
        )

        min_bitlen = min(
            bitlen for _, bitlen, _ in self.decoding_table
        )

        current_bits = 0
        current_bitlen = 0

        completed = False

        while values or current_bitlen:
            while values and current_bitlen < max_bitlen:
                current_bits <<= 8
                current_bits |= ord(values[0])
                current_bitlen += 8
                values = values[1:]

            if current_bitlen < min_bitlen:
                break

            consumed_bitlen = None
            found = False

            for bits, bitlen, symbol in self.decoding_table:
                if current_bitlen < bitlen:
                    continue

                if bitlen == current_bitlen:
                    to_compare = current_bits
                else:
                    to_compare = (current_bits >> (current_bitlen - bitlen)) & ((1 << bitlen) - 1)

                if bits == to_compare:
                    found = True
                    consumed_bitlen = bitlen

                    if symbol == '\x00':
                        completed = True
                    else:
                        decoded.append(symbol)

                    break

            assert(found)

            current_bits &= (1 << (current_bitlen - consumed_bitlen)) - 1
            current_bitlen -= consumed_bitlen

            if completed:
                break

        if current_bitlen > 8:
            values = chr(current_bits & 0xFF) + values

        return ''.join(decoded), values

    def train(self, frequences):
        import heapq

        queue = []

        for value, frequency in frequences:
            heapq.heappush(queue, Node(value, frequency))

        A = None

        while True:
            A = heapq.heappop(queue)
            try:
                B = heapq.heappop(queue)
                heapq.heappush(queue, Root(A, B))
            except IndexError:
                break

        encoding_table = {}

        def _make_tree(root, prefix=0):
            if root is None:
                return

            elif type(root) == Root:
                return (
                    _make_tree(root.A, (prefix << 1) | 0),
                    _make_tree(root.B, (prefix << 1) | 1)
                )

            else:
                encoding_table[root.value] = prefix
                return root.value

        self.decoding_tree = _make_tree(A)
        self._generate_table()


class TmpResult(object):
    __slots__ = (
        'encoded_tables', 'encoded', 'rest', 'table_id'
    )

    def __init__(self, encoded_tables, encoded, rest, table_id):
        self.encoded_tables = encoded_tables
        self.encoded = encoded
        self.rest = rest
        self.table_id = table_id


class DnsEncoder(object):
    __slots__ = (
        'tables', 'encoders'
    )

    TABLE_FREEDNS = 0b00
    TABLE_TLDS = 0b01
    TABLE_TERM = 0b10
    TABLE_GENERIC = 0b11

    # ENCODING:
    # 3 bits - AMOUNT OF PARTS
    # [ 2 bits - ID of table ] [ 2 bits - ID of table ] ...
    # RECORD \0 RECORD \0 TLD

    def __init__(self, tables=None):

        if tables is None:
            from .dns_encoder_table import TREES
            tables = TREES

        mappings = {
            'generic': self.TABLE_GENERIC,
            'tlds': self.TABLE_TLDS,
            'terms': self.TABLE_TERM
        }

        self.tables = tables
        self.encoders = {
            mappings[table]: Huffman(decoding_table=tables[table]) for table in tables
            if table in mappings
        }

    def encode(self, data):
        data = data.lower()

        def _recursive_encoder(encoded_tables, encoded, rest):
            if not rest:
                return encoded_tables, encoded

            elif len(rest) == 1:
                try:
                    this_encoded = self.encoders[self.TABLE_TLDS].encode(rest[0], last=True)
                    return encoded_tables, encoded + this_encoded

                except ValueError:
                    pass

            results = []

            generic_encoded_tables = list(encoded_tables)
            generic_encoded_tables.append(self.TABLE_GENERIC)

            for merged_parts in xrange(2, len(rest)+1):
                joined_rest = '.'.join(rest[:merged_parts])
                not_joined_rest = rest[merged_parts:]

                generic_encoded_tables, generic_encoded = _recursive_encoder(
                    generic_encoded_tables, encoded + self.encoders[self.TABLE_GENERIC].encode(
                        joined_rest, last=not bool(not_joined_rest)), not_joined_rest)

                results.append(TmpResult(
                    generic_encoded_tables, generic_encoded, not_joined_rest, self.TABLE_GENERIC))

            word = rest[0]
            joined_rest = '.'.join(rest)

            for idx, domain in enumerate(FREEDNS):
                if word == domain:
                    this_encoded_tables = list(encoded_tables)
                    this_encoded_tables.append(self.TABLE_FREEDNS)
                    this_encoded_tables, this_encoded = _recursive_encoder(
                        this_encoded_tables, encoded + chr(idx), rest[1:]
                    )
                    results.append(TmpResult(
                        this_encoded_tables, this_encoded, rest[1:], self.TABLE_FREEDNS))
                    break

                elif joined_rest == domain:
                    this_encoded_tables = list(encoded_tables)
                    this_encoded_tables.append(self.TABLE_FREEDNS)
                    this_encoded_tables, this_encoded = _recursive_encoder(
                        this_encoded_tables, encoded + chr(idx), []
                    )
                    results.append(TmpResult(
                        this_encoded_tables, this_encoded, [], self.TABLE_FREEDNS))
                    break

            for encoder in self.encoders:
                this_encoded_tables = list(encoded_tables)
                this_encoded_tables.append(encoder)
                try:
                    this_rest = rest[1:]
                    this_encoded_tables, this_encoded = _recursive_encoder(
                        this_encoded_tables, encoded + self.encoders[encoder].encode(
                            word, last=not bool(this_rest)), this_rest)
                except ValueError:
                    # Not possible, retry
                    continue

                results.append(TmpResult(
                    this_encoded_tables, this_encoded, rest[1:], encoder))

            best = sorted(results, key=lambda x: len(x.encoded))[0]
            return best.encoded_tables, best.encoded

        rest = data.rsplit('.', 3)
        tables, data = _recursive_encoder([], '', rest)

        tables_map = 0b0
        for table in tables:
            tables_map <<= 2
            tables_map |= table
        tables_map |= len(tables) << 6
        return chr(tables_map) + data

    def decode(self, data):
        tables_map_encoded = ord(data[0])
        encoded = data[1:]
        decoded = []
        tables = []
        tables_cnt = (tables_map_encoded >> 6) & 0b11

        for idx in xrange(tables_cnt):
            tables.insert(0, (tables_map_encoded >> (idx * 2)) & 0b11)

        for table in tables:
            decoded_part, encoded = self.encoders[table].decode(encoded)
            decoded.append(decoded_part)

        if encoded:
            decoded_part, encoded = self.encoders[self.TABLE_TLDS].decode(encoded)
            decoded.append(decoded_part)

        return '.'.join(decoded), encoded


if __name__ == '__main__':
    import zstd
    import sys
    import io

    TLDS = (
        'aaa', 'aarp', 'abarth', 'abb', 'abbott', 'abbvie', 'abc', 'able', 'abogado',
        'abudhabi', 'ac', 'academy', 'accenture', 'accountant', 'accountants', 'aco',
        'actor', 'ad', 'adac', 'ads', 'adult', 'ae', 'aeg', 'aero', 'aetna', 'af',
        'afamilycompany', 'afl', 'africa', 'ag', 'agakhan', 'agency', 'ai', 'aig',
        'aigo', 'airbus', 'airforce', 'airtel', 'akdn', 'al', 'alfaromeo', 'alibaba',
        'alipay', 'allfinanz', 'allstate', 'ally', 'alsace', 'alstom', 'am',
        'americanexpress', 'americanfamily', 'amex', 'amfam', 'amica', 'amsterdam',
        'analytics', 'android', 'anquan', 'anz', 'ao', 'aol', 'apartments', 'app',
        'apple', 'aq', 'aquarelle', 'ar', 'arab', 'aramco', 'archi', 'army', 'arpa',
        'art', 'arte', 'as', 'asda', 'asia', 'associates', 'at', 'athleta', 'attorney',
        'au', 'auction', 'audi', 'audible', 'audio', 'auspost', 'author', 'auto',
        'autos', 'avianca', 'aw', 'aws', 'ax', 'axa', 'az', 'azure', 'ba', 'baby',
        'baidu', 'banamex', 'bananarepublic', 'band', 'bank', 'bar', 'barcelona',
        'barclaycard', 'barclays', 'barefoot', 'bargains', 'baseball', 'basketball',
        'bauhaus', 'bayern', 'bb', 'bbc', 'bbt', 'bbva', 'bcg', 'bcn', 'bd', 'be',
        'beats', 'beauty', 'beer', 'bentley', 'berlin', 'best', 'bestbuy', 'bet', 'bf',
        'bg', 'bh', 'bharti', 'bi', 'bible', 'bid', 'bike', 'bing', 'bingo', 'bio',
        'biz', 'bj', 'black', 'blackfriday', 'blockbuster', 'blog', 'bloomberg',
        'blue', 'bm', 'bms', 'bmw', 'bn', 'bnl', 'bnpparibas', 'bo', 'boats',
        'boehringer', 'bofa', 'bom', 'bond', 'boo', 'book', 'booking', 'bosch',
        'bostik', 'boston', 'bot', 'boutique', 'box', 'br', 'bradesco', 'bridgestone',
        'broadway', 'broker', 'brother', 'brussels', 'bs', 'bt', 'budapest', 'bugatti',
        'build', 'builders', 'business', 'buy', 'buzz', 'bv', 'bw', 'by', 'bz', 'bzh',
        'ca', 'cab', 'cafe', 'cal', 'call', 'calvinklein', 'cam', 'camera', 'camp',
        'cancerresearch', 'canon', 'capetown', 'capital', 'capitalone', 'car',
        'caravan', 'cards', 'care', 'career', 'careers', 'cars', 'cartier', 'casa',
        'case', 'caseih', 'cash', 'casino', 'cat', 'catering', 'catholic', 'cba',
        'cbn', 'cbre', 'cbs', 'cc', 'cd', 'ceb', 'center', 'ceo', 'cern', 'cf', 'cfa',
        'cfd', 'cg', 'ch', 'chanel', 'channel', 'charity', 'chase', 'chat', 'cheap',
        'chintai', 'christmas', 'chrome', 'chrysler', 'church', 'ci', 'cipriani',
        'circle', 'cisco', 'citadel', 'citi', 'citic', 'city', 'cityeats', 'ck', 'cl',
        'claims', 'cleaning', 'click', 'clinic', 'clinique', 'clothing', 'cloud',
        'club', 'clubmed', 'cm', 'cn', 'co', 'coach', 'codes', 'coffee', 'college',
        'cologne', 'com', 'comcast', 'commbank', 'community', 'company', 'compare',
        'computer', 'comsec', 'condos', 'construction', 'consulting', 'contact',
        'contractors', 'cooking', 'cookingchannel', 'cool', 'coop', 'corsica',
        'country', 'coupon', 'coupons', 'courses', 'cr', 'credit', 'creditcard',
        'creditunion', 'cricket', 'crown', 'crs', 'cruise', 'cruises', 'csc', 'cu',
        'cuisinella', 'cv', 'cw', 'cx', 'cy', 'cymru', 'cyou', 'cz', 'dabur', 'dad',
        'dance', 'data', 'date', 'dating', 'datsun', 'day', 'dclk', 'dds', 'de',
        'deal', 'dealer', 'deals', 'degree', 'delivery', 'dell', 'deloitte', 'delta',
        'democrat', 'dental', 'dentist', 'desi', 'design', 'dev', 'dhl', 'diamonds',
        'diet', 'digital', 'direct', 'directory', 'discount', 'discover', 'dish',
        'diy', 'dj', 'dk', 'dm', 'dnp', 'do', 'docs', 'doctor', 'dodge', 'dog',
        'domains', 'dot', 'download', 'drive', 'dtv', 'dubai', 'duck', 'dunlop',
        'duns', 'dupont', 'durban', 'dvag', 'dvr', 'dz', 'earth', 'eat', 'ec', 'eco',
        'edeka', 'edu', 'education', 'ee', 'eg', 'email', 'emerck', 'energy',
        'engineer', 'engineering', 'enterprises', 'epson', 'equipment', 'er',
        'ericsson', 'erni', 'es', 'esq', 'estate', 'esurance', 'et', 'etisalat', 'eu',
        'eurovision', 'eus', 'events', 'everbank', 'exchange', 'expert', 'exposed',
        'express', 'extraspace', 'fage', 'fail', 'fairwinds', 'faith', 'family', 'fan',
        'fans', 'farm', 'farmers', 'fashion', 'fast', 'fedex', 'feedback', 'ferrari',
        'ferrero', 'fi', 'fiat', 'fidelity', 'fido', 'film', 'final', 'finance',
        'financial', 'fire', 'firestone', 'firmdale', 'fish', 'fishing', 'fit',
        'fitness', 'fj', 'fk', 'flickr', 'flights', 'flir', 'florist', 'flowers',
        'fly', 'fm', 'fo', 'foo', 'food', 'foodnetwork', 'football', 'ford', 'forex',
        'forsale', 'forum', 'foundation', 'fox', 'fr', 'free', 'fresenius', 'frl',
        'frogans', 'frontdoor', 'frontier', 'ftr', 'fujitsu', 'fujixerox', 'fun',
        'fund', 'furniture', 'futbol', 'fyi', 'ga', 'gal', 'gallery', 'gallo',
        'gallup', 'game', 'games', 'gap', 'garden', 'gb', 'gbiz', 'gd', 'gdn', 'ge',
        'gea', 'gent', 'genting', 'george', 'gf', 'gg', 'ggee', 'gh', 'gi', 'gift',
        'gifts', 'gives', 'giving', 'gl', 'glade', 'glass', 'gle', 'global', 'globo',
        'gm', 'gmail', 'gmbh', 'gmo', 'gmx', 'gn', 'godaddy', 'gold', 'goldpoint',
        'golf', 'goo', 'goodyear', 'goog', 'google', 'gop', 'got', 'gov', 'gp', 'gq',
        'gr', 'grainger', 'graphics', 'gratis', 'green', 'gripe', 'grocery', 'group',
        'gs', 'gt', 'gu', 'guardian', 'gucci', 'guge', 'guide', 'guitars', 'guru',
        'gw', 'gy', 'hair', 'hamburg', 'hangout', 'haus', 'hbo', 'hdfc', 'hdfcbank',
        'health', 'healthcare', 'help', 'helsinki', 'here', 'hermes', 'hgtv', 'hiphop',
        'hisamitsu', 'hitachi', 'hiv', 'hk', 'hkt', 'hm', 'hn', 'hockey', 'holdings',
        'holiday', 'homedepot', 'homegoods', 'homes', 'homesense', 'honda',
        'honeywell', 'horse', 'hospital', 'host', 'hosting', 'hot', 'hoteles',
        'hotels', 'hotmail', 'house', 'how', 'hr', 'hsbc', 'ht', 'hu', 'hughes',
        'hyatt', 'hyundai', 'ibm', 'icbc', 'ice', 'icu', 'id', 'ie', 'ieee', 'ifm',
        'ikano', 'il', 'im', 'imamat', 'imdb', 'immo', 'immobilien', 'in', 'inc',
        'industries', 'infiniti', 'info', 'ing', 'ink', 'institute', 'insurance',
        'insure', 'int', 'intel', 'international', 'intuit', 'investments', 'io',
        'ipiranga', 'iq', 'ir', 'irish', 'is', 'iselect', 'ismaili', 'ist', 'istanbul',
        'it', 'itau', 'itv', 'iveco', 'jaguar', 'java', 'jcb', 'jcp', 'je', 'jeep',
        'jetzt', 'jewelry', 'jio', 'jll', 'jm', 'jmp', 'jnj', 'jo', 'jobs', 'joburg',
        'jot', 'joy', 'jp', 'jpmorgan', 'jprs', 'juegos', 'juniper', 'kaufen', 'kddi',
        'ke', 'kerryhotels', 'kerrylogistics', 'kerryproperties', 'kfh', 'kg', 'kh',
        'ki', 'kia', 'kim', 'kinder', 'kindle', 'kitchen', 'kiwi', 'km', 'kn', 'koeln',
        'komatsu', 'kosher', 'kp', 'kpmg', 'kpn', 'kr', 'krd', 'kred', 'kuokgroup',
        'kw', 'ky', 'kyoto', 'kz', 'la', 'lacaixa', 'ladbrokes', 'lamborghini',
        'lamer', 'lancaster', 'lancia', 'lancome', 'land', 'landrover', 'lanxess',
        'lasalle', 'lat', 'latino', 'latrobe', 'law', 'lawyer', 'lb', 'lc', 'lds',
        'lease', 'leclerc', 'lefrak', 'legal', 'lego', 'lexus', 'lgbt', 'li',
        'liaison', 'lidl', 'life', 'lifeinsurance', 'lifestyle', 'lighting', 'like',
        'lilly', 'limited', 'limo', 'lincoln', 'linde', 'link', 'lipsy', 'live',
        'living', 'lixil', 'lk', 'llc', 'loan', 'loans', 'locker', 'locus', 'loft',
        'lol', 'london', 'lotte', 'lotto', 'love', 'lpl', 'lplfinancial', 'lr', 'ls',
        'lt', 'ltd', 'ltda', 'lu', 'lundbeck', 'lupin', 'luxe', 'luxury', 'lv', 'ly',
        'ma', 'macys', 'madrid', 'maif', 'maison', 'makeup', 'man', 'management',
        'mango', 'map', 'market', 'marketing', 'markets', 'marriott', 'marshalls',
        'maserati', 'mattel', 'mba', 'mc', 'mckinsey', 'md', 'me', 'med', 'media',
        'meet', 'melbourne', 'meme', 'memorial', 'men', 'menu', 'merckmsd', 'metlife',
        'mg', 'mh', 'miami', 'microsoft', 'mil', 'mini', 'mint', 'mit', 'mitsubishi',
        'mk', 'ml', 'mlb', 'mls', 'mm', 'mma', 'mn', 'mo', 'mobi', 'mobile', 'mobily',
        'moda', 'moe', 'moi', 'mom', 'monash', 'money', 'monster', 'mopar', 'mormon',
        'mortgage', 'moscow', 'moto', 'motorcycles', 'mov', 'movie', 'movistar', 'mp',
        'mq', 'mr', 'ms', 'msd', 'mt', 'mtn', 'mtr', 'mu', 'museum', 'mutual', 'mv',
        'mw', 'mx', 'my', 'mz', 'na', 'nab', 'nadex', 'nagoya', 'name', 'nationwide',
        'natura', 'navy', 'nba', 'nc', 'ne', 'nec', 'net', 'netbank', 'netflix',
        'network', 'neustar', 'new', 'newholland', 'news', 'next', 'nextdirect',
        'nexus', 'nf', 'nfl', 'ng', 'ngo', 'nhk', 'ni', 'nico', 'nike', 'nikon',
        'ninja', 'nissan', 'nissay', 'nl', 'no', 'nokia', 'northwesternmutual',
        'norton', 'now', 'nowruz', 'nowtv', 'np', 'nr', 'nra', 'nrw', 'ntt', 'nu',
        'nyc', 'nz', 'obi', 'observer', 'off', 'office', 'okinawa', 'olayan',
        'olayangroup', 'oldnavy', 'ollo', 'om', 'omega', 'one', 'ong', 'onl', 'online',
        'onyourside', 'ooo', 'open', 'oracle', 'orange', 'org', 'organic', 'origins',
        'osaka', 'otsuka', 'ott', 'ovh', 'pa', 'page', 'panasonic', 'paris', 'pars',
        'partners', 'parts', 'party', 'passagens', 'pay', 'pccw', 'pe', 'pet', 'pf',
        'pfizer', 'pg', 'ph', 'pharmacy', 'phd', 'philips', 'phone', 'photo',
        'photography', 'photos', 'physio', 'piaget', 'pics', 'pictet', 'pictures',
        'pid', 'pin', 'ping', 'pink', 'pioneer', 'pizza', 'pk', 'pl', 'place', 'play',
        'playstation', 'plumbing', 'plus', 'pm', 'pn', 'pnc', 'pohl', 'poker',
        'politie', 'porn', 'post', 'pr', 'pramerica', 'praxi', 'press', 'prime', 'pro',
        'prod', 'productions', 'prof', 'progressive', 'promo', 'properties',
        'property', 'protection', 'pru', 'prudential', 'ps', 'pt', 'pub', 'pw', 'pwc',
        'py', 'qa', 'qpon', 'quebec', 'quest', 'qvc', 'racing', 'radio', 'raid', 're',
        'read', 'realestate', 'realtor', 'realty', 'recipes', 'red', 'redstone',
        'redumbrella', 'rehab', 'reise', 'reisen', 'reit', 'reliance', 'ren', 'rent',
        'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant', 'review',
        'reviews', 'rexroth', 'rich', 'richardli', 'ricoh', 'rightathome', 'ril',
        'rio', 'rip', 'rmit', 'ro', 'rocher', 'rocks', 'rodeo', 'rogers', 'room', 'rs',
        'rsvp', 'ru', 'rugby', 'ruhr', 'run', 'rw', 'rwe', 'ryukyu', 'sa', 'saarland',
        'safe', 'safety', 'sakura', 'sale', 'salon', 'samsclub', 'samsung', 'sandvik',
        'sandvikcoromant', 'sanofi', 'sap', 'sarl', 'sas', 'save', 'saxo', 'sb', 'sbi',
        'sbs', 'sc', 'sca', 'scb', 'schaeffler', 'schmidt', 'scholarships', 'school',
        'schule', 'schwarz', 'science', 'scjohnson', 'scor', 'scot', 'sd', 'se',
        'search', 'seat', 'secure', 'security', 'seek', 'select', 'sener', 'services',
        'ses', 'seven', 'sew', 'sex', 'sexy', 'sfr', 'sg', 'sh', 'shangrila', 'sharp',
        'shaw', 'shell', 'shia', 'shiksha', 'shoes', 'shop', 'shopping', 'shouji',
        'show', 'showtime', 'shriram', 'si', 'silk', 'sina', 'singles', 'site', 'sj',
        'sk', 'ski', 'skin', 'sky', 'skype', 'sl', 'sling', 'sm', 'smart', 'smile',
        'sn', 'sncf', 'so', 'soccer', 'social', 'softbank', 'software', 'sohu',
        'solar', 'solutions', 'song', 'sony', 'soy', 'space', 'sport', 'spot',
        'spreadbetting', 'sr', 'srl', 'srt', 'ss', 'st', 'stada', 'staples', 'star',
        'starhub', 'statebank', 'statefarm', 'stc', 'stcgroup', 'stockholm', 'storage',
        'store', 'stream', 'studio', 'study', 'style', 'su', 'sucks', 'supplies',
        'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv', 'swatch', 'swiftcover',
        'swiss', 'sx', 'sy', 'sydney', 'symantec', 'systems', 'sz', 'tab', 'taipei',
        'talk', 'taobao', 'target', 'tatamotors', 'tatar', 'tattoo', 'tax', 'taxi',
        'tc', 'tci', 'td', 'tdk', 'team', 'tech', 'technology', 'tel', 'telefonica',
        'temasek', 'tennis', 'teva', 'tf', 'tg', 'th', 'thd', 'theater', 'theatre',
        'tiaa', 'tickets', 'tienda', 'tiffany', 'tips', 'tires', 'tirol', 'tj',
        'tjmaxx', 'tjx', 'tk', 'tkmaxx', 'tl', 'tm', 'tmall', 'tn', 'to', 'today',
        'tokyo', 'tools', 'top', 'toray', 'toshiba', 'total', 'tours', 'town',
        'toyota', 'toys', 'tr', 'trade', 'trading', 'training', 'travel',
        'travelchannel', 'travelers', 'travelersinsurance', 'trust', 'trv', 'tt',
        'tube', 'tui', 'tunes', 'tushu', 'tv', 'tvs', 'tw', 'tz', 'ua', 'ubank', 'ubs',
        'uconnect', 'ug', 'uk', 'unicom', 'university', 'uno', 'uol', 'ups', 'us',
        'uy', 'uz', 'va', 'vacations', 'vana', 'vanguard', 'vc', 've', 'vegas',
        'ventures', 'verisign', 'versicherung', 'vet', 'vg', 'vi', 'viajes', 'video',
        'vig', 'viking', 'villas', 'vin', 'vip', 'virgin', 'visa', 'vision',
        'vistaprint', 'viva', 'vivo', 'vlaanderen', 'vn', 'vodka', 'volkswagen',
        'volvo', 'vote', 'voting', 'voto', 'voyage', 'vu', 'vuelos', 'wales',
        'walmart', 'walter', 'wang', 'wanggou', 'warman', 'watch', 'watches',
        'weather', 'weatherchannel', 'webcam', 'weber', 'website', 'wed', 'wedding',
        'weibo', 'weir', 'wf', 'whoswho', 'wien', 'wiki', 'williamhill', 'win',
        'windows', 'wine', 'winners', 'wme', 'wolterskluwer', 'woodside', 'work',
        'works', 'world', 'wow', 'ws', 'wtc', 'wtf', 'xbox', 'xerox', 'xfinity',
        'xihuan', 'xin', 'xn--11b4c3d', 'xn--1ck2e1b', 'xn--1qqw23a', 'xn--2scrj9c',
        'xn--30rr7y', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--3hcrj9c',
        'xn--3oq18vl8pn36a', 'xn--3pxu8k', 'xn--42c2d9a', 'xn--45br5cyl',
        'xn--45brj9c', 'xn--45q11c', 'xn--4gbrim', 'xn--54b7fta0cc', 'xn--55qw42g',
        'xn--55qx5d', 'xn--5su34j936bgsg', 'xn--5tzm5g', 'xn--6frz82g',
        'xn--6qq986b3xl', 'xn--80adxhks', 'xn--80ao21a', 'xn--80aqecdr1a',
        'xn--80asehdb', 'xn--80aswg', 'xn--8y0a063a', 'xn--90a3ac', 'xn--90ae',
        'xn--90ais', 'xn--9dbq2a', 'xn--9et52u', 'xn--9krt00a', 'xn--b4w605ferd',
        'xn--bck1b9a5dre4c', 'xn--c1avg', 'xn--c2br7g', 'xn--cck2b3b', 'xn--cg4bki',
        'xn--clchc0ea0b2g2a9gcd', 'xn--czr694b', 'xn--czrs0t', 'xn--czru2d',
        'xn--d1acj3b', 'xn--d1alf', 'xn--e1a4c', 'xn--eckvdtc9d', 'xn--efvy88h',
        'xn--estv75g', 'xn--fct429k', 'xn--fhbei', 'xn--fiq228c5hs', 'xn--fiq64b',
        'xn--fiqs8s', 'xn--fiqz9s', 'xn--fjq720a', 'xn--flw351e', 'xn--fpcrj9c3d',
        'xn--fzc2c9e2c', 'xn--fzys8d69uvgm', 'xn--g2xx48c', 'xn--gckr3f0f',
        'xn--gecrj9c', 'xn--gk3at1e', 'xn--h2breg3eve', 'xn--h2brj9c', 'xn--h2brj9c8c',
        'xn--hxt814e', 'xn--i1b6b1a6a2e', 'xn--imr513n', 'xn--io0a7i', 'xn--j1aef',
        'xn--j1amh', 'xn--j6w193g', 'xn--jlq61u9w7b', 'xn--jvr189m', 'xn--kcrx77d1x4a',
        'xn--kprw13d', 'xn--kpry57d', 'xn--kpu716f', 'xn--kput3i', 'xn--l1acc',
        'xn--lgbbat1ad8j', 'xn--mgb9awbf', 'xn--mgba3a3ejt', 'xn--mgba3a4f16a',
        'xn--mgba7c0bbn0a', 'xn--mgbaakc7dvf', 'xn--mgbaam7a8h', 'xn--mgbab2bd',
        'xn--mgbah1a3hjkrd', 'xn--mgbai9azgqp6j', 'xn--mgbayh7gpa', 'xn--mgbb9fbpob',
        'xn--mgbbh1a', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgbca7dzdo',
        'xn--mgberp4a5d4ar', 'xn--mgbgu82a', 'xn--mgbi4ecexp', 'xn--mgbpl2fh',
        'xn--mgbt3dhd', 'xn--mgbtx2b', 'xn--mgbx4cd0ab', 'xn--mix891f', 'xn--mk1bu44c',
        'xn--mxtq1m', 'xn--ngbc5azd', 'xn--ngbe9e0a', 'xn--ngbrx', 'xn--node',
        'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--nyqy26a', 'xn--o3cw4h', 'xn--ogbpf8fl',
        'xn--otu796d', 'xn--p1acf', 'xn--p1ai', 'xn--pbt977c', 'xn--pgbs0dh',
        'xn--pssy2u', 'xn--q9jyb4c', 'xn--qcka1pmc', 'xn--qxam', 'xn--rhqv96g',
        'xn--rovu88b', 'xn--rvc1e0am3e', 'xn--s9brj9c', 'xn--ses554g', 'xn--t60b56a',
        'xn--tckwe', 'xn--tiq49xqyj', 'xn--unup4y', 'xn--vermgensberater-ctb',
        'xn--vermgensberatung-pwb', 'xn--vhquv', 'xn--vuq861b', 'xn--w4r85el8fhu5dnra',
        'xn--w4rs40l', 'xn--wgbh1c', 'xn--wgbl6a', 'xn--xhq521b', 'xn--xkc2al3hye2a',
        'xn--xkc2dl3a5ee0h', 'xn--y9a3aq', 'xn--yfro4i67o', 'xn--ygbi2ammx',
        'xn--zfr164b', 'xxx', 'xyz', 'yachts', 'yahoo', 'yamaxun', 'yandex', 'ye',
        'yodobashi', 'yoga', 'yokohama', 'you', 'youtube', 'yt', 'yun', 'za', 'zappos',
        'zara', 'zero', 'zip', 'zm', 'zone', 'zuerich', 'zw'
    )


    class CTDictBuilder(object):
        __slots__ = (
            'terms', 'generic', 'tlds', 'cdns', 'freedns'
        )

        def __init__(self, ct_stats):
            # CSV.ZSTD
            # CTID;ORG;IP;PRIV;PUB

            self.terms = {
                '-': 1
            }
            self.generic = {}
            self.tlds = {}
            self.cdns = {}
            self.freedns = {}

            with open(ct_stats, 'rb') as fh:
                dctx = zstd.ZstdDecompressor()
                with dctx.stream_reader(fh) as reader:
                    wrap = io.TextIOWrapper(io.BufferedReader(reader), encoding='utf8')
                    while True:
                        line = wrap.readline().lower()
                        line = line.strip()

                        if not line:
                            break

                        try:
                            _, _, _, priv, pub = line.split(';')
                        except ValueError:
                            continue

                        if priv == '*' or all(x in 'abcdef1234567890' for x in priv):
                            priv = ''

                        if not all(x in DNS_ALPHABET+'*;' for x in priv):
                            continue

                        if not all(x in DNS_ALPHABET+'*;' for x in pub):
                            continue

                        for freedns in FREEDNS:
                            if pub.endswith('.'+freedns):
                                self._inc_freedns(freedns)
                                break

                        for tld in TLDS:
                            if pub.endswith('.'+tld):
                                self._inc_tld(tld)

                                non_tld = pub[:-(len(tld)+1)]
                                generic = '.'.join(x for x in [priv, non_tld] if x)

                                self._inc_generic(generic)
                                for term in non_tld.split('.'):
                                    self._inc_term(term)

                                for term in priv.split('.'):
                                    self._inc_term(term)

                                break

        def _inc_tld(self, tld):
            if not tld:
                return

            if tld not in self.tlds:
                self.tlds[tld] = 0

            self.tlds[tld] += 1

        def _inc_generic(self, generic):
            if not generic:
                return

            for c in generic:
                if c == '*':
                    continue

                if c not in self.generic:
                    self.generic[c] = 0

                self.generic[c] += 1

        def _inc_term(self, term):
            if not term:
                return

            if term not in self.terms:
                self.terms[term] = 0

            self.terms[term] += 1

            to_leave = []

            if len(self.terms) > 32768*16:
                for term in list(self.terms):
                    if self.terms[term] > 1:
                        to_leave.append(term)

                if len(to_leave) > 32768:
                    to_leave = sorted(
                        to_leave, key=lambda x: self.terms[x],
                        reverse=True
                    )[:32768]

                self.terms = {
                    k: self.terms[k] for k in to_leave
                }

        def _inc_cdn(self, cdn):
            if not cdn:
                return

            if cdn not in self.cdns:
                self.terms[cdn] = 0

            self.terms[cdn] += 1

        def _inc_freedns(self, freedns):
            if not freedns:
                return

            if freedns not in self.freedns:
                self.freedns[freedns] = 0

            self.freedns[freedns] += 1

        def make_trees(self):
            trees = {}

            for freq in self.__slots__:
                max_key = 0
                table = getattr(self, freq)
                work_table = {}
                for idx, key in enumerate(sorted(table, key=lambda x:table[x], reverse=True)):
                    if idx > 511:
                        break

                    work_table[key] = table[key]
                    if table[key] > max_key:
                        max_key = table[key]

                work_table[IS_END] = max_key + 1

                h = Huffman()
                table = work_table.items()

                if not table:
                    print(("EMPTY TABLE", table))
                    continue

                h.train(table)
                trees[freq] = h.decoding_table

            return trees

    trees = CTDictBuilder(sys.argv[1]).make_trees()
    with open(sys.argv[2], 'w+') as out:
        out.write('# -*- encoding: utf-8 -*-\n\n')
        out.write('TREES={}\n'.format(repr(trees)))
