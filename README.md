An implementation of zero-knowledge proof, non-interactive version
based on [NARWHAL](http://ojs.pythonpapers.org/index.php/tppm/article/download/155/142) implementation of Brandon Lum Jia Jun’s [ZKA_wzk](https://courses.csail.mit.edu/6.857/2014/files/15-cheu-jaffe-lin-yang-zkp-authentication.pdf) auth protocol.

== Usage:

Suppose you’re using an anonymous channel and want ephemeral sort of identity. `signature_b64` method let you sign you post using a private key, or password, in this example, “Owls are not they seem”: 
```
ZKProofMark.signature_b64(
  "Diane, I’m holding in my hand a small box of chocolate bunnies.",
  "Owls are not that they seem")
```
Result is Base64-encoded; you can put it then after your post as a literal signature:
```
Diane, I’m holding in my hand a small box of chocolate bunnies.
AAAAJh/xkpcVl79B0MOnBQ+sR+04bk3bb8O3+q4dRCo+FnXrJa1XMr2Q
```
This signature by itself reveals nothing. But after that, you can create a proof that it is you (or at least a person that knows the same private key) created this post, with another message:
```
ZKProofMark.prove_b64(
  "I’d like to brush my teeth.",
  "Diane, I’m holding in my hand a small box of chocolate bunnies.",
  "Owls are not that they seem")
```
You can then post the result, together with the message. Note that the text of message is necessary for proof to work. Also note that whitespace is significant.
```
I’d like to brush my teeth.
AAAAICBaJzQDO99fONnz1SBBWltzY60ecFPod1piSFK3jmbT::
AAAAQQDmV0w44uH2K7IAdjl4w4U9iI8GC0xde3W9aMQ4HAim0UYXQoIir0Ot
r3adxoWPkiru1DOJYPPfEB26eqVFno6x

```
Anyone having the access to these two messages can prove that they are created with the same private key:

```
ZKProofMark.check_b64(
"AAAAICBaJzQDO99fONnz1SBBWltzY60ecFPod1piSFK3jmbT::
AAAAQQDmV0w44uH2K7IAdjl4w4U9iI8GC0xde3W9aMQ4HAim0UYXQoIir0Ot
r3adxoWPkiru1DOJYPPfEB26eqVFno6x", "I’d like to brush my teeth.",
"Diane, I’m holding in my hand a small box of chocolate bunnies.",
"AAAAJh/xkpcVl79B0MOnBQ+sR+04bk3bb8O3+q4dRCo+FnXrJa1XMr2Q")
```
Without `_b64` postfix, all methods return (or, in case of `check`, expect) OpenSSL::BN bignums. Base64 versions are just for convenience of storage.

You can set salt before operations; it is useful if you, for instance, writing an application and want a signature for given message and private key to be different from signature from same message and key in any other application. Proof, on the other hand, is based on a random value and is always come out different, even for same input values.
