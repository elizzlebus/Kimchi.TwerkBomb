#!/usr/bin/env python

###############################################################################
# Summary
###############################################################################

'''
Pykemons has a list of pykemons you can catch, including a flag. However, it's rarity is set to 0, so you can never capture it by chance. Flask sends a list of possible pykemons as a variable in the session object. So we want to be able to decode the session object which is sent as cookies to the client side.
'''

###############################################################################
# Decoding
###############################################################################
import base64
import zlib

cookie = "eJzlmF1vozgUhv_KiuteEAidIVIvhkz5iBpGIRMMrEYrY2chiSEohCRQ9b_vMWm-aD5Wu6m00l612MbmPH7Pe077KoSYsVzotMQHgeAiipdC51XIytk4madC5_dfbw_CYj5PTkdfBTrOyWKSLSf8-VX4LRQ6wshkM4rshWWwyjKeozFy89BQZUvXFCzpy1BqR9SIY9rVysCzWYh6eeD1I3-ovb-nlpbRy4jhzny0joixianJ1tTrPwnwHXEmdFT5QUhxMv5wKF-QTsjs4mQ2oR_Gf_zc7rzAi8myFDqPQCHP4PfDFhi14kByqxdZUwLTneJSWYcJgdfeHs5jcKWYhRNNxBzDUehEYkUg93PAI1qGwmjilpapxRRQkFITw1KbkMSNARF7iZ72IbeVjyGngbTJiOkmwfvCc6F_WNRAcJifDlrHGJQbGCSaY09rBYlfEENJL6OAQ0ofwvPlQYThprGkrGitgq8RRkoCKgAUm5gklFmmUwbIBeW4hWW0YiLbzDL0IuhqM5LoGSAtqOeUGLkFNftRkPZW4ZBjHkVcZYFnRdTstcIkj3ykzCwT5mWnOkZ5Tj27D7yI8WRBA-FuTumvn06U9OU6QgioCpAtvqRaEdSvXkOIEV1B-BmoZOp7WuwnG0CjJhBirSJqgLJKLaMmJJXhRwFSROz1WGjOIj_RQbO1utYkUVM4eWkZDqjseYsJcFPDhTOU1DJsxYf9iAxnSKNir0D1DLb6o66o72RBE1s9Nx0ox8jkW8hYCml0W3Gf7kGP0j09yJ5a9_cgzjiUnNiXHSXs1sqJjxEcJ4-P6FZNhpOFiVr5HihgfUga6Yz_HDb_dkUBzUVNFeznv1sn_iPdUoIKd2OLY7T-D6hBPoPnn6uhX40-RQ0ilb7WFgyhDcZoGYdIBZu1wXJ1MUCDyE9nEexaBJ6T-aW2BG_gtSH34RkwHdRwRvx884sq2E82wuXjZT86tc3W9XCpSVe3LfPeBfix_fkF2Bf_FwX4nHruUoA_KOmeBfh-yXOm__gXybP-hOQZPdsjJ13-6JvOn7auVvi7Xoxd1bYNssGVUxJT3IfTaobjzDaas76QEMeTx-HU49VzdRzKlUikIPcRua17EeDHW-O3IcXhImSubVaAzufBUGPjWu8t9jLRdLACGKdzjHhnxe2Bv6dXoeEy0l3D5cMlS2pBZCcOUycfDzXIQBsuX4F1PQXyZUWTXRcGuYH0ktdcKFWQD4PiWrGoP_SiAHaTTQHw8WaxUG8IwNBFf3jzzxcj5u3Ckc7jGJ6hsXSnkN6ZLzFxPGxVFGpj3TSa2goq15zXTe6y2HM48jlYyYKU7Qj2Y0SCNsPT1hwL4F8BMgY4l_waDvvqed2wSnFtR9x2qNeDloTwGg3XomSBFIv7a9o6-xSbI3D2DQs87cRqlDOoF9A2zOngsmOfLGgg3879HJ20Ku3ryN8_8G-0KRipO9UBcl3CCH4etymAHXc1sJReCthkjp6U0JJwXOk3QAT4JKV66WoxKI5bVYXhiihXr6GusOTOauwo3yP60jrTuvAPudi67CabrQsft6vnhh3dqGIGW9HuXo6_Hnb_YPiDzIt0CRvADS74QeLb2184ZkxD==="
compressed_data = base64.urlsafe_b64decode(cookie)
print(zlib.decompress(compressed_data))

'''
$ python decrypt.py  | grep '"rarity":0'
 
$ echo "UENURntOMHRfNF9zaDFueV9NNGcxazRycH0=" | base64 -d
PCTF{N0t_4_sh1ny_M4g1k4rp}
'''
