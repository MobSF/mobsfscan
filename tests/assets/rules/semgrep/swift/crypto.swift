
// ruleid:ios_sha1_collision
_ = SHA1(data)
// ruleid:ios_sha1_collision
_ = CC_SHA1(data)
// ruleid:ios_weak_hash
_ = MD5(data)
// ruleid:ios_weak_hash
_ = CC_MD5(data)
// ruleid:ios_insecure_random_no_generator
_ = Int.random(in: 0..<10)
// ruleid:ios_insecure_random_no_generator
_ = arc4random()
