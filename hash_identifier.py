class HashPattern:
    def __init__(self, name, confidence, reason, prefix = None, length = None):
        self.name = name
        self.confidence = confidence
        self.reason = reason
        self.prefix = prefix
        self.length = length

    hex_characters = set('0123456789abcdefABCDEF')

    def matches(self, hash_string):
        # prefix-based pattern
        if self.prefix is not None:
            return hash_string.startswith(self.prefix)

        # length-based pattern
        if self.length is not None:
            if len(hash_string) != self.length:
                return False
            return all(c in self.hex_characters for c in hash_string)

        return False

class HashIdentifier:
    def __init__(self, patterns):
        self.patterns = patterns

    def identify(self, hash_string):
        matches = []
        for pattern in self.patterns:
            if pattern.matches(hash_string):
                matches.append(pattern)
        return matches


# string
bcrypt = HashPattern(name='bcrypt', confidence='high', reason='bcrypt PHC string', prefix='$2b$')
sha512_crypt = HashPattern(name='SHA-512 crypt', confidence='high', reason='Unix crypt(3), used in /etc/shadow', prefix='$6$')
apache_md5 = HashPattern(name='Apache MD5-crypt', confidence='high', reason='Apache htpasswd MD5 variant', prefix='$apr1$')
phpass = HashPattern(name='phpass', confidence='high', reason='WordPress / phpBB password hash', prefix='$P$')
django_pbkdf2 = HashPattern(name='Django PBKDF2-SHA256', confidence='high', reason='Django default password hash', prefix='pbkdf2_sha256$')
ldap_ssha = HashPattern(name='LDAP SSHA', confidence='high', reason='LDAP salted SHA-1 (base64 payload)', prefix='{SSHA}')
argon2id = HashPattern(name='Argon2id', confidence='high', reason = 'Argon2id is a PHC string', prefix = '$argon2id$')

# length number
md5 = HashPattern(name='MD5', confidence='medium', reason = '32 hex characters', length=32)
ntlm = HashPattern(name='NTLM', confidence='medium', reason='32 hex characters, common on Windows/AD', length=32)
sha1 = HashPattern(name='SHA-1', confidence='medium', reason='40 hex characters', length=40)
sha224 = HashPattern(name='SHA-224', confidence='medium', reason='56 hex chars', length=56)
sha256 = HashPattern(name='SHA-256', confidence='medium', reason='64 hex chars', length=64)
sha384 = HashPattern(name='SHA-384', confidence='medium', reason='96 hex chars', length=96)
sha512 = HashPattern(name='SHA-512', confidence='medium', reason='128 hex chars', length=128)

ALL_PATTERNS = [
    bcrypt,
    sha512_crypt,
    apache_md5,
    phpass,
    django_pbkdf2,
    ldap_ssha,
    argon2id,
    md5,
    ntlm,
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
]

identifier = HashIdentifier(ALL_PATTERNS)

while True:
    hash_string = input("Enter a hash to identify (or 'quit' to exit): ")
    if hash_string == 'quit':
        break

    result = identifier.identify(hash_string)

    if not result:
        print("No match found.")
    elif len(result) == 1:
        r = result[0]
        print(f"{r.name} ({r.confidence}) — {r.reason}")
    else:
        names = [r.name for r in result]
        print(f"This matches {len(result)} possible hash types: {', '.join(names)}")
        print("Length/charset alone can't tell these apart — context matters (where did this hash come from?).")
        for r in result:
            print(f"  - {r.name} ({r.confidence}) — {r.reason}")