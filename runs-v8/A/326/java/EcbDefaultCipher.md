## Verdict
Real issue. Cipher instantiation without explicit mode defaults to ECB, which does not provide semantic security.

## Source
Line 21: `Cipher cipher = Cipher.getInstance("AES");`

The call to `Cipher.getInstance("AES")` without specifying a cipher mode parameter defaults to ECB (Electronic Codebook) mode. ECB encrypts each plaintext block independently with the same key, producing identical ciphertext for identical plaintext blocks. This leaks plaintext patterns and is cryptographically inadequate.

## Fix
Replace `"AES"` with an explicit, semantically secure mode:

```java
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
```

Or, for authenticated encryption:

```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
```

CBC with PKCS5Padding is a standard choice compatible with most Java versions. GCM provides both confidentiality and authenticity (integrity protection).

If using CBC, you also need to generate and prepend an initialization vector (IV) to the ciphertext so decryption can retrieve it. A new random IV should be generated for each encryption:

```java
SecureRandom random = new SecureRandom();
byte[] iv = new byte[16];
random.nextBytes(iv);
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
```

The IV should be transmitted with or prepended to the ciphertext (IVs are not secret, only random and unique per message).

## Explanation
CWE-326 covers use of weak or incorrect cryptographic algorithms. ECB mode is the cipher suite default in Java but is inherently weak because it does not randomize the output—identical plaintext blocks always encrypt to identical ciphertext blocks under the same key. This reveals patterns in the plaintext and violates semantic security.

The fix specifies an explicit mode (CBC or GCM) that is semantically secure: the same plaintext block encrypts differently each time due to the IV (or because GCM includes the message counter or prior state). For CBC, an IV is required during initialization and should be generated randomly for each message.
