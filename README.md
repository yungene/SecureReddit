# Note
Please do not use it for university coursework without referencing the source.

This project was done as part of coursework for CSU34031 Advanced Telecommunications module.

# SecureReddit

Secure communication through encrypted posts and comments on Reddit. Allows to send encrypted messages to a group of users.

The user stores its public key in a pinned posts in its profile in a pre-defined format. 

# Some details

_In summary, the users of the app need to have a Reddit account which is also used to identify users in the system. Each user participating in the secure system has an RSA public key published on Reddit and pinned on their profile. The messages are also exchanged by means of Reddit posts, the recipients are tagged in the comments. When a user is tagged in a comment, Reddit sends a notification to that user. That way a recipient can easily track all the incoming encrypted messages._

_The system uses symmetric keys yo encrypt the message. Symmetric keys themselves are encrypted using assymetric public keys before they are published. Each symmetric key is only used once for a single message and thus is not stored persistently on the sender's system. It is only published in an encrypted form as a comment under a submission with the message encrypted via that key._

_Messages are encrypted using AES symmetric block cipher in CBC mode with key length being 128 bits. AES is a fast and secure algorithm that is widely used for symmetric encryption. A single new session key is generated for each message and is shared within the group. A message is then encrypted via the generated key and is published as a post submission in the format that also includes author's name and  IV used in encryption._

_Sharing of the session key within the group is done by means of encrypting the session key with each group member's asymmetric public key and publishing the resulting ciphertext as a comment under the encrypted message._

_Decryption directly follows from encryption. The tagged recipient receives a notification into their Reddit inbox. They parse the comment in which they were tagged and extract the ciphertext. The recipient then uses its own private key to decrypt the ciphertext into the session key. The recipient then parses the submission to extract the encrypted message and IV. At this stage the recipient has all the necessary information to decrypt the message using standard AES decryption._
