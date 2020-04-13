import praw
import config
import pprint
import parsing
import traceback
import user
import time
from base64 import b64encode, b64decode

# This file provides functions for secure communication over Reddit.

# Login using the credentails from config.py.
# Returns the reddit client.
def login():
    r = praw.Reddit(user_agent = "test bot",
                username = config.username,
                password = config.password,
                client_id = config.client_id,
                client_secret = config.client_secret)
    print("logged in")
    return r

def submit_post(client, subreddit, title, body):
    my_post = client.reddit.subreddit(subreddit).submit(title, selftext=body)
    return my_post

# Submit the posts using the protocol defined.
def submit_secure(client, subreddit, title, body, group_id):
    # ecrypt the title and the body using symmetric key
    session_key, cipher_msg = parsing.encrypt_message(client,body);

    # submit a post
    my_post = submit_post(client, subreddit, title, cipher_msg);
    print(client.groups.groups)
    if group_id in client.groups.groups:
        users = client.groups.get_users(group_id);
        for user in users:
            user_key_t = get_public_key(client.reddit,user);
            print(user_key_t);

            user_key = parsing.parse_public_key(user_key_t)
            if user_key is not None:
                print(user_key);
                c_session_key = parsing.ecnrypt_symm_key(user,user_key,session_key);
                for i in range(10):
                    try:
                        my_post.reply(c_session_key);
                        break;
                    except praw.exceptions.APIException:
                        # Attempt to deal with popetial rate limit.
                        traceback.print_exc()
                        time.sleep(3)

        return True;
    return False;

# Retrieve the public key of a user from its Reddit profile.
def get_public_key(reddit, user):
    top = list(reddit.redditor(user).submissions.top(limit=5))
    for post in top:
        if post.pinned:
            if is_valid_key(post):
                return post.selftext
    return ""

def is_valid_key(post):
    key = parsing.parse_public_key(post.selftext)
    return key is not None

# Get decrypted posts
def get_my_posts(client, mark_unread=False):
    messages_c = get_my_raw_posts(client, 25);
    posts_t = []
    for message in messages_c:
        try:
            if mark_unread:
                if (not message.new) :
                    continue
                message.mark_read()
            user, key_c = parsing.parse_symm_key(message.body)
            if(user is None):
                continue
            print(key_c)
            p_symm_key = parsing.decrypt_symm_key(client.key, key_c)
            post = message.submission
            post_text_c = post.selftext
            sender, iv, msg_c = parsing.parse_message(post_text_c)
            print("sym key:" + str(p_symm_key))
            post_text_p = parsing.decrypt_message(p_symm_key, iv, msg_c)
            posts_t.append("By:%s || post: %s \n" % (message.author.name,  post_text_p))
        except Exception:
            print("Error in decrypting a comment %s\n" % (message.body))
            traceback.print_exc()
    return posts_t


def get_my_raw_posts(client, n):
    return client.reddit.inbox.mentions(limit=n);

def update_public_key(client, always_generate_new=True):
    key = None
    if not always_generate_new:
        key = parsing.get_priv_key(client);
    else:
        key = parsing.generate_key(client);
    pub_key = key.publickey().export_key();
    pk = b64encode(pub_key).decode('utf-8')
    f_pub_key = parsing.public_key_format % (pk);
    my_post = submit_post(client,'test','my_key',f_pub_key);
    client.key = key

def setup_client():
    client = user.User(config.username);
    print(config.username);
    client.reddit = login();
    client.key = parsing.get_priv_key(client);
    return client