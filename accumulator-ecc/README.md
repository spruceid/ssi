# Bilinear-map Accumulators

Bilinear accumulators work on curves that support bilinear pairings instead of groups of unknown order.
These groups require smaller order than unknown-order for the same level of security. Thus proofs, witnesses, and
accumulator values are much smaller. However, more of the burden for zero-knowledge proofs is put upon provers
than verifiers with the benefit that verifying proofs can be done in constant time independent of the number of data
elements.

This implementation draws upon work from [Nguyen05](https://eprint.iacr.org/2005/123/), [DT08](https://eprint.iacr.org/2008/538/), [CKS08](https://eprint.iacr.org/2008/539/), [ATSM09](https://ro.uow.edu.au/cgi/viewcontent.cgi?referer=&httpsredir=1&article=9405&context=infopapers), [Thakur19](https://eprint.iacr.org/2019/1147/), [BUV20](https://eprint.iacr.org/2020/598/), [VB20](https://eprint.iacr.org/2020/777/).
