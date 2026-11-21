"""
happ_parser.py - Multi-Protocol Deep-Link Decryptor for Bunker-Auto-Engine.
Supports:
  1. Happ deep-links: happ://crypt (RSA-1024), crypt2-4 (RSA-4096), crypt5 (ChaCha20-Poly1305 / AES-GCM)
  2. INCY links: incy://crypt1 (AES-256-GCM authenticated sub envelopes)
  3. V2RayTun import wrappers: v2raytun://import (nested base64 / URL unwrap)
"""

import base64
import hashlib
import json
import logging
import os
import re
import urllib.parse
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

_ENGINE_DIR = Path(__file__).resolve().parent

# Embedded PKCS#1 RSA private keys for crypt1–crypt4
HAPP_RSA_KEYS_B64 = [
    'MIICXwIBAAKBgQCxsS7PUq1biQlVD92rf6eXKr9oG1/SrYx3qWahZP+Jq35m4Wb/Z+mB6eBWrPzJ/zZpZLWLQorcvOKt+sLaCHyH1HLNkti4jlaEQX6x97XgBm8GK08+lLLWquFDhWRNxsrfzJyNdpVopzBRmCJKTc8ObYyPbrv9T35a8Kd5WqjnUwIDAQABAoGBAJoqe85skPPF5U7jwRM2YhUJhZ+xgGWtJR3834pPslWjcLuZ/F7DrRiF7ZnF5FztDCxMsCXuycPSLWl9EulQS5mrL/fnwpK2jVE8O1Em9RsBOOrWwzuZnAuooRIb/8zC0fvH2oGkk60zSKycMe69uvYUDjhvULX2Spjmf9CS9/HhAkEA3I797En/DrpAZz6NM4GqZ1mkH0kEX/kAHLP1lBgYL1kVK455EG/ecJkMJmtK7A+fWw0N0IcxrpYAbbOAo19vjwJBAM4+0MAZ8TIZUk6Rs2gYUo04A6mYUy5MWtRa9pyFIgD71oHDR+1jrnPLqQyCj0tfbZBc1iVgsisJBpocC8sKaf0CQQDRNd3Mxb/nY2p1xJLBmaxezlvsxSEePB4MG/PFXzmJqBF5uHJD0imIWtR4mOt/ka4R+wbwl1zcAzMy28MYtQ0nAkEAuUILWML0uL+uAw01TeerH1aVU52T+h5z6BPdOTMNHD0arWywCzhi13i03JvaAyYw0F/Tq7dz0txEpeFTZopwMQJBANnHbzB87/xTjDQA4/L8sSU8m0vM1nRWmJIaAC94pcM+KDGLnbBhWrvZGy8Zg8vQwNvdvCLvylk0jVTTFqW3ibM=',
    'MIIJKQIBAAKCAgEA5cL2yu9dZGnNbs4jt222NugIqiuZdXKdTh4IgXZmOX0vdpW+rYWrPd1EObQ3Urt+YBTK5Di98EBjYCPr8tusaVRAn3Vaq41CDisEdX35u1N8jSHQ0zDOtPdrvJtlqShib4UI6Vybk/QSmoZVbpRb67TNsiFqBmK1kxT+mbtHkhdT2u+hzNLQr0FtJR1+gC+ELKZ48zZY/d3YSSRSb+dxUnd4FH31Kz68VKqlajISSzIrGQWc/zqSlihIvfnTPNX3pCyJpwAuYXieWSRDAogrwGwoiN++y14OLYHrNlqzoJ44WM3Tbm7x1Dj/8QI3tzwixli/0JmqQ19ssETDbVQ90asoPc4QFhyc4c+PH62AdK1S+ysXt5uqEujRBk3rC53l65IOVXSTZgsLwzS7EFY9lZszJXUJJh5GB9heO8c7PNCTOxno3l4684iHFJuxnkS0DLbdzCXfovwfIP8q3lj7UJswPKVHkCLNSUutNke+xex1J3YEdvebJzv7Dk78PqLRmLWaEsAhQanXs93aTxEkd/p7hgFV30QozVQ/oNAvmQSVIBd6zCGM3of3R3tmDkDNGQGrY4MBTX+cTJGYstdhQXxj1oFZEG16F/0GGXG+sia67gYM3OC7RWyBOzULsEmupIiM8Vdx1iErw7yvJSC4IsIsWZD8JAmZtLBqEQ/TvfcCAwEAAQKCAgATc0nJLDJPydUmSDUl1hfS1hnFriMzmhxO/KPjsc49l6do9oxJzEMO3ahk6ii0zEKKh7gVUehialD/Vosm6AnUcNl3pkuisjahVGrwN1Xo0cx9dhtjhYI6N6fbM5yLkWuj3TM/7iMNh1/7zNt2nQCbF5dCOSnsmHaemOxkv0Hz0B29LwQXftFDxNokhjarS1p5HS6oCDXIZ/tjVbvU1Vb2kD6OHYufuZPf5wJR1yNNUlXrrFn6EU9PfuGJk5iaUdLBBzQv+wfyIG/nQ/aYREbP51gXHjncpX21xIXQ+CS0uDA09FetxZ6bRKgGExX8YQ7gk6rJUfjj8zQUR/3zR2pkKHRywANzu32VnSvFFtEL7+EuM0XA03MZStGuRb3/QjO+I2JOV+Ec+VVc9OYangwu8+mQC1NnCWe49LZX04hc/xlRqW4kaWcpbT7xGTIeSrWhR7cBjUvgc7NNDnKla8mXSW5/6iSi2Vl83CBm78+ao+Pwbtk/D6n3fM4c3FNiBDyWHJ27C8HLicDhSiQqZUuO203zBZrstUNN7tkmMvaHlavrvL0ajBIJD27Vo/uZ61OVYEPDybNJlRFsaRNirIYCHk2DBte6nqbZ7Hvm+3iIk928vz1dyQdZ4bLPO5onxTFAcfny8pruXnnS/aTXvaHlzTc84z5mBPR94VRqOEKrAQKCAQEA9VUEaz2XWdQuafQo6CIx2YGcBKcmQfpbBtfHb+V4BBko9BzU3ao6AGSXS54LMktnAmKjqbXkjjaMKKEHj85BbchlDoXqaSU9Xnq7wO20xn18OxNCkPdxHzzN4/HT78nRbCOxteBv4V56HsZit2a2eaBokqUuirQTZBqNpLgkPOR/wrV/Tk9RvOG4IVYxvl1TIZdp2VXqpxHceu+aE0JgQ2kj8N70w6YUOgjxRFLirr4tsPvJFs6XflogEXwsMtJGsN7Esy4uNlBGSd6JjLFuUtALXCZbx5wgKauqyJctmtqd1dllnpqAfe1eZL/aVyd2tyRg0MzqacZVs28lcuEIYQKCAQEA78CegneDbIdPyTW2+YDVVYUMQcIkxF82CnEql1GS2nIewhlKOYsAXrWln4NLdHltKX6POhfmWO5WA5ERD7v0NmNw9Q/+3je6BXx1RasExXYOqwcz7UAni95p6ZZBTP/j0fFZQYLzUC7Yg5eBDP8rKFR0MV5FnWW7fYxC5+bJY5dZH8A7Jqkt9lrNo4gmfAgbHhFoOFY6X3E7r3UTpx0XtQNQeCZ8sDF9RULSHep6EA0Kg8JtUdjbpBiTvrC/frCiXwJU+QufqPnN2sDH2UL5Dt+ZKMmp9l6wMdJiK2wMlmruAEuW9I4zDtb36txm6ZrZfQxN6HQyRXRe53bJzjAFVwKCAQEA3+1g4i3Otwxn7QgSSofjrl+SM+EJl5FXgrBz9puh50O70M18MnPNC0zFmBzCpX6ToGa+cgp3eqMpXXBWAZnGuNj//LiZFK4MDO/D7j5KEh65xQY4bS+eDmAmode6lhVFVQpji9o25KOinfKAalyTVALpUGj7SVlClc1y2hXF5dq/Ds8xSx41Qk1ZDvyo3NQ8K94TnG/ChgpUj9WhcdDVItKWHqazDN3LeoltBusMw2kNNY0sp+eb+ZVzzeHkSeMK6Sf8rHwLbEHrVkOMk2HkjCwfIlZU0aac6MwrT3pGAyFmjaooChOGEusVjKpdNc3smw/WWt+fWzrQQL7DlM74IQKCAQEAkxeKKGFKsHsT6E6cQ9dXC3DlZDLIe/IuJZnol43km0EIvezmLQeq4nBvfL4AvSUCZELRfMLNACK5gtatsQmPew7nbnKx24Q1DMie6m9SLhOQTD3PDfAeUyHRuQ4GYkdcbqG0MQ02WitjitiYxHCI+eVWpDNCYp7XuN8k7UIarI9ejqxRnhaNrGdpYrtVYSNX/8qONoIwrf26sJsTw6OFt/iglhaGyVKTmLq2TsRcvxxBJzVR/LUfjD3H52ZpFkEoXUIBAAqxmeoo8dz0v8bnJsjoHq4bKJxPXUHGGP3heyd/fY7ivoe/q4sX72/pc8kdRisWYVdowFP1Je0rQuUTYQKCAQAbxOYko2rkl95CSgTeRGHIlCwHeftXzaeFknaxnXBBAhm6LV5pxBllE/NH3Hcpmjwl7oZpeC4Iny9mdXZ0TH/1KgHRfWMJH/h2Ipg+IjRReIEZcWQnVOhkCjvmR6KccYWIGdkDg5OvETeQaZb8t5VUAwMJQP2yTafRS/PC3SSRWnbkN8rqOteU0jZxwDqHfRD5Es5jjhIOL/jtSgXic0Ro1+/VAMqvetiZ+xIsnUvDTChu7sFuL/rzndptvJ2NHHp8TbCwJAODOitU3Dd7HJfM2ERnmH0DZwzuaFdWnKPyJWBXddFYaNQxlfzr6IuPy6b213MHGKnFf8l2C5u32Bo+',
    'MIIJJwIBAAKCAgEAlBetA0wjbaj+h7oJ/d/hpNrXvAcuhOdFGEFcfCxSWyLzWk4SAQ05gtaEGZyetTax2uqagi9HT6lapUSUe2S8nMLJf5K+LEs9TYrhhBdx/B0BGahA+lPJa7nUwp7WfUmSF4hir+xka5ApHjzkAQn6cdG6FKtSPgq1rYRPd1jRf2maEHwiP/e/jqdXLPP0SFBjWTMt/joUDgE7v/IGGB0LQ7mGPAlgmxwUHVqP4bJnZ//5sNLxWMjtYHOYjaV+lixNSfhFM3MdBndjpkmgSfmgD5uYQYDL29TDk6Eu+xetUEqry8ySPjUbNWdDXCglQWMxDGjaqYXMWgxBA1UKjUBWwbgr5yKTJ7mTqhlYEC9D5V/LOnKd6pTSvaMxkHXwk8hBWvUNWAxzAf5JZ7EVE3jt0j682+/hnmL/hymUE44yMG1gCcWvSpB3BTlKoMnl4yrTakmdkbASeFRkN3iMRewaIenvMhzJh1fq7xwX94otdd5eLB2vRFavrnhOcN2JJAkKTnx9dwQwFpGEkg+8U613+Tfm/f82l56fFeoFN98dD2mUFLFZoeJ5CG81ZeXrH83niI0joX7rtoAZIPWzq3Y1Zb/Zq+kK2hSIhphY172Uvs8X2Qp2ac9UoTPM71tURsA9IvPNvUwSIo/aKlX5KE3IVE0tje7twWXL5Gb1sfcXRzsCAwEAAQKCAgAK3VHMFCHlQaiqvHNPNMWRGp0JJl27Ulw3U1Q9p+LC3OWNknyvpxC5EJPQbTUXhlO2A9AiDOXmaj5EMavTAaj0tzWhLlrVVQ/CSJYS4sVyAY67GyTpOIxmYtPBE3YY6vTU1SSoU2dqnMDnfwAbM2g0QXatXYRDGPYLLNHHp7R27IBpBTJeDwb2qEA1BBC/3WXsfVy6cfhWrrB7fH4F9tuEtG+sp+N2fbDcFnDH1hbQAm+HEXKzWMpRcSmX+rQ2wDlLW/N3utI+TzP4Vx5zTuT3QCsDYzeRgSJ4CjMwKKSGZ3QDF5cDCVJdsJ24fRl+mpBWoLqqBS7gzFVYsTx88GNs5jl9D7ZndIEOKYhtA00NgF+0N1Vs7IbgfoBfwABSFoiukBcre2NvJ4jVxApy09IiN6E/HBZ/qhH3q+1k9nLFgzH9VsBXuucgjlSFXzVLLQilfsd7LEaX8ytGDAiAC3RLbIhDRX3ruv0ufRSwhUoGd4ps+cgHrKGUGqz4pdjOzWFNTzpTTYuxkoMbklI+HIFQcstNLW0mryBcWhldqLhYNGH5w4fX+J/wkxbH1Yh9slPWT+WX69/l9myysscXxSlev9Ycty4rNWt9kohNHvBd5ZxlePD5ngTmCZ2PjisUS1Kvmy9rjzRjP2qNoxmXmTbp3QJymuF1RjtRHxlqHGVlgQKCAQEA0S/SnC+BUlUxxCVQ+qNE8FAe5EWdNgSlz1ep5NGcOBUgpFStHJBGdzSc1Ht6MuBd+2Gqfzi46CR5BbyaC9i3P0X4347wKjrzPQ39l1kGideRKEKMAbmj2SdaU7kYWFhddurGssp4xzojNG0BYkR/0kEnHeCu/RJ6HVwv5K5vyhYsAwKeWeTS3T06KElgy4uNNRRAqI9ZJamrU7ZfIQ7YBHsCWlgFwx7Hu7rQS8dOPmd4TW0Xs32yEDfDymw98e4kxNME01Z9Q55uShLwXo4g+wp/6SYL363OyR/MqSAW66IthPqz6WnJ37hmk2SZsUip9tBHPdJyvACHeNR9SP4VMwKCAQEAtTvMeW0QvNWK7+VM2cnm2viFPpqGWDaccI6Zct/Qb6cO05xdRtarm/QjM3vXjjN4ALj4gPkz014oPEcHJe5Y6ma1tGmy01cltvYoUsfxYHX2jUiaI9EmmOIR/9gSiAZn+P9RjNx9Q/hHT9ul+H5FnitC9wV0TZ7egu3ROKuZ7t5EhdogO5lC8qUn6GrVIdj9eDAGkHWdO6v3cqYuP6cV6yiBOK2CikW+MnLC8yXGwvWX7iW4/2f0xBP+NWgXPzZu627FC8EDmZv8TEGppd5RsJNcQOraXnq7foEzHCB2MsvJrDbHAmTqKaWKzoxR+dzJOSt1sHbhNXoKKnsEqd112QKCAQAcq2c8DK62sAJwFYUxtKrAHNr/AiN3wc9PyX35ZFj6vrqIiypmncdqkwVjgcDPtDxtNYd+hDGjb0w+4whh00PaIibnzNlRkF7B4Wb+FS92ONsmH2i828p++ovAqb+SbBnzMF4nJuTCuU8V4lKsOyMhl9hame6htKST3Yya1OVxVvSVPQii3V+g/sE3wEbJ3shtm+b4sxzOsqBOitIi37vvcURzSVkQ0ukg64uctyYcG2Y7hlYXPYToAByPY6Jhw/e6GgmxRUtJty76a/oRm30dquS4+YPrFhEfM4KDM2iwxrtiXFHIDb2jMcytKr59s63Hq+f3qx4aciAfCVBabqhNAoIBAFZl8p20k/Uh7EFfVBrDeO3M6mCk9ATbzAqQwLCV6F1CC/xvn7wknN0VLy7dDC77dGsLw1Rg+Qb77TyHM+4uSW89lcQzW5ALDKzDfwevz++HbQl/ohQPIlJh++i3DmaQf0KiHTOE7abYls6ITQBA2lmEEEGI9SAH69YJH+PfUtwgVBRnn1QqRVM9zt+rBn5DXtrMMmTt3Q5UdfvPI18u/XEE902Y0hGvG/Qa57tYt/+7azmZ/C6uVW6ghWDahbKZ9ZkBTqjC1D+HsGh+KS0s5k7CgYllLMM7yWSOnVn8U7z1j+gsmQUYLNW72IeNN4thaQB7Knj8w3JmArCrwtZkAEkCggEANfI5YqEYgq/Mt4NeTTHG5PoRuy1cRzJLB8QCRF5O2GLij/jl61zSdbeczsNqJzufnxKx49Okkesy9xKVAcT2QMJ55V38wekpJk0p3wdEhgdBLhOO6kY6R9dhy74e8LFDERH/MfRuvOhBcLqjGb6xGnedf3yyIFm5Mt4aWOVxLyqUQGF76Dj+PQXjwmQBjxsgxrBAf2UVm/4eb8aX/2xlWDjJ8eXXR+4PaoA7jR4tsfW7z0iYqA+GUQ0zTcINJdoSTbypxkT8iVQI3VAWcKILnNcoZS4Q1n9PKHp8L9qHLGlIgt2jOpwKaYDChgoJI5+9WJFarSi7yX1pBXgMfD7aHA==',
    'MIIJKQIBAAKCAgEA3UZ0M3L4K+WjM3vkbQnzozHg/cRbEXvQ6i4A8RVN4OM3rK9kU01FdjyoIgywve8OEKsFnVwERZAQZ1Trv60BhmaM76QQEE+EUlIOL9EpwKWGtTL5lYC1sT9XJMNP3/CI0gP5wwQI88cY/xedpOEBW72EmOOShHUm/b/3m+HPmqwc4ugKj5zWV5SyiT829aFA5DxSjmIIFBAms7DafmSqLFTYIQL5cShDY2u+/sqyAw9yZIOoqW2TFIgIHhLPWek/ocDU7zyOrlu1E0SmcQQbLFqHq02fsnH6IcqTv3N5Adb/CkZDDQ6HvQVBmqbKZKf7ZdXkqsc/Zw27xhG7OfXCtUmWsiL7zA+KoTd3avyOh93Q9ju4UQsHthL3Gs4vECYOCS9dsXXSHEY/1ngU/hjOWFF8QEE/rYV6nA4PTyUvo5RsctSQL/9DJX7XNh3zngvif8LsCN2MPvx6X+zLouBXzgBkQ9DFfZAGLWf9TR7KVjZC/3NsuUCDoAOcpmN8pENBbeB0puiKMMWSvll36+2MYR1Xs0MgT8Y9TwhE2+TnnTJOhzmHi/BxiUlY/w2E0s4ax9GHAmX0wyF4zeV7kDkcvHuEdc0d7vDmdw0oqCqWj0Xwq86HfORu6tm1A8uRATjb4SzjTKclKuoElVAVa5Jooh/uZMozC65SmDw+N5p6Su8CAwEAAQKCAgBLlgyNoqFZxWjZZmHiSXr7bUdxCEkfkM8Nn8dcky12O8fB6mv39LZcrF22u+UIDIgec31Igq1G4e5ojd62LDAQLCnKlp2SJMeLo1ILTYTYtPJuJUqSolPuhzeKbFl1ouHp88e2sUMpmwJT6UpFj0L6hqOr4lkjfC1kktXPXvSe3lpDvIYXBrlFU5slPP3WLE5RaLW+w4gE6nt9+FS6xkJHQHhP1odE+z8B0EV/HdhvKTCnWz4bGj4azlkPhNdl3EKLS6axTlti/hq9yT6d7owlu4sKnkqGF18deei8hoJ4eWvHo7a12BfQHuKJJJ6Qgb1jzQv+tm9XEZ7qCxaMtwHabrjnIDM57xvJAO4fKX5L3/hN+Zx8q4dFsHhOOnJ1As18YChkYJXF9zcUGEztoiDBUQJAIrMJHWFJOtxj78fP18LYOjbhUL1H3IdKLLr1duX9aGM9lAgJV66l/rWlyePh+pBMriTbOAnXEsQFVvjzzzyBZznBZYCJow/KmZO3WciFbSETqq3FqoE3HwvxsjlaC4gpHWqa40lGtjFvPnIHS6MbH7LwVcAldDrjuqNJMd5lWhPAnYVj7JYER230X2HQ3BBrrAZ7Zae1lrJfdQs0zjYiyHdOAmTEtWnkuSadknecHrL4RYoZtdTriZT42N+tcbJAb5GLr3FOVwV6IhEEWQKCAQEA/AZ7xHIZmI6KcWWoYQVP2Ibmjv+DZYGAtyoYd+hnV9KiGAddJWknbZycCZU4qyG63+wEEFEoPJ3KfEqUwGHVK5jaexLP/BbgR9nwt3UF1IhDs3D8UrS79YFihuvcz+hlGDsrcTj8DZkoVAsMom0I4lsTNqauH+o0I6UYLrRswcIlbKG6yJN1B08Nbz88l8qCLLhRMXJ2yxfSch20T28UggS2bZnpEws5DY5I1C6irGRIyaLNVEi076Dp9OZ8RCnXn7KfXnZntl0AvQVUaOvTt2fh9X4Qnk5XADfUoZ2it1HIinNQOLpnhoNa2/cpGoG3tPnXaY8NNC3dt/dyCahTJQKCAQEA4MPSOuD98dv3V3GY/ODyDphzQOHxp+dHiDcY1TjLcJs3XVuPgMSL0GGBrhn5yiKKjir2mNdsdDtS2qwZVp2fZI2oUunMMZ2tila+Wa+AMUZyvUP6OFRs/qu24mVsNizV5Ad7/d/mEmfoMnRQk0Eg0dx1GNelhcdd0GvyaKAu1/uvKt97BaKLHhfC41keO1GNGXeASSSfIa5jlXQngVSPzh5C+rhtgv+z9KkyGHXUxiflisQlgKmDAXBSwNZxoVUYxqCFRX9RNQkQmokws+z3k02w/gF+L1bkw1UFsBfcsU1eWfi0q2h/B6CLjspsWIpppEK13DWs+oD3qx+67LwTgwKCAQEAxrEF2rZp35BhLU2MFhFuBbM1Cf//w4L5y23wpHghIWf6Sx9jHB9u6kfR7OwsJR8OiYM1IPga1M9B2AOkipeWzCxR8z29o20VnRABa2FjG0/isBGfnETI+qDq4JwLFg6NxTDA6x6V+NKKrNeZOmTj4DEVULzQAnFOcduy2P99zrQVdTN8Yq1+UijM2qvsRW9ueXtG58jqRuudCkLI6OcWL/svJ/Fzg4QRktJeMIojze2yROWJI62+mD0wtdcQmVyzlj/ozTxkP63K6zrMdXuXCr1ns3eT+nqgtJdPl6sDoatkg2KuGEs9WxssAsc1LKSgBJoEbkBNlJmkd2kqCtsd0QKCAQA8mc+m/F67xTkNJJ3BIM1izgvVJJZJVPxeZ6yUYLnJZLAqxbMNXvDrgD68uFg2/dUpu7+9OegN9qjCOMCkL9939xG5OTxK7F6L/BNajw0bPAlXqmpeobS5fYbTx9DDUpdg4fu2WZXoxIdAg0fuTBMTQkN4LTx9s2FB/rjfKME4jq2N+69pt4eW14U+Uxrpl3VZtnSqQ+t7408KTsUQA8K6KkKY4vzz4wmcH7pYCf0SaFNldLk/1XRzANvvDmKYwx7o/wKv2EIG8Ki/Ydn1ySB/YOUltzVUgjMvz063SdfBHkEgNQRRat1FKy41k7JetQMCvNHXy8kVyYv9YZK+nX8NAoIBAQCT1QG6UYZFHbdXuxmyDxVAprLPn1SpEy1NBlJLOWjjvUHFENnnUq8zbqPcPFDpXo04UQ8S31+lPXw3cZUpI4oFdrIM1h+cPKz7dV4tpZvb3nWqsTqLhtM2KzM+E3ZDjlHgyq/Sw+HLeLHobyI7OlbEnU/vubwQv2xpTvwumflqF9ANkDG3Pm7cYQC7k7jlpLQy5XRuclb9zhPzje0+Ytf7TntijWyMYnMwh4TbOOhjnL8iLs1D5GeSy2RV30uNR6D9XbSE/MsVqb71C2mvRhePuZRLk64Lx4+d28LcIk3akHMl9HeBPIvEsn94aC2K+oxaCl2Dv/tAsj62kypSh1/t'
]

_loaded_keys = []

def _get_key(index: int):
    if not CRYPTO_AVAILABLE or index < 0 or index >= len(HAPP_RSA_KEYS_B64):
        return None
    global _loaded_keys
    if not _loaded_keys:
        _loaded_keys = [None] * len(HAPP_RSA_KEYS_B64)
    if _loaded_keys[index] is None:
        raw_b64 = HAPP_RSA_KEYS_B64[index]
        pem_lines = "\n".join([raw_b64[i:i+64] for i in range(0, len(raw_b64), 64)])
        pem = f"-----BEGIN RSA PRIVATE KEY-----\n{pem_lines}\n-----END RSA PRIVATE KEY-----"
        try:
            _loaded_keys[index] = serialization.load_pem_private_key(pem.encode(), password=None)
        except Exception as e:
            logging.error(f'Failed to load Happ key {index}: {e}')
            return None
    return _loaded_keys[index]

def b64_decode_urlsafe(s: str) -> bytes:
    s = s.strip().replace('-', '+').replace('_', '/')
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return base64.b64decode(s)

def decrypt_happ_link(link_or_path: str) -> Optional[str]:
    """
    Decrypts a Happ deep-link (happ://crypt/..., happ://crypt2/..., crypt3, crypt4).
    Returns decrypted URL or proxy configuration text.
    """
    link = link_or_path.strip()
    if link.startswith('happ://'):
        path = link[7:]
    else:
        path = link

    ordinal = -1
    payload = ''

    if path.startswith('crypt5/'):
        return decrypt_happ_crypt5(path[7:])
    elif path.startswith('crypt4/'):
        ordinal = 3
        payload = path[7:]
    elif path.startswith('crypt3/'):
        ordinal = 2
        payload = path[7:]
    elif path.startswith('crypt2/'):
        ordinal = 1
        payload = path[7:]
    elif path.startswith('crypt/'):
        ordinal = 0
        payload = path[6:]
    else:
        return None

    key = _get_key(ordinal)
    if not key:
        return None

    try:
        cipher_bytes = b64_decode_urlsafe(payload)
        key_size = key.key_size // 8
        plain_parts = []
        for i in range(0, len(cipher_bytes), key_size):
            chunk = cipher_bytes[i:i + key_size]
            plain_parts.append(key.decrypt(chunk, padding.PKCS1v15()))
        return b''.join(plain_parts).decode('utf-8', errors='ignore')
    except Exception as e:
        logging.warning(f'Failed decrypting Happ {path[:15]}: {e}')
        return None


# ============================================================================
# HAPP CRYPT5 (ChaCha20-Poly1305 / AES-GCM + Marker RSA)
# ============================================================================

def swap_pairs_bytes(b: bytes) -> bytes:
    """Adjacent byte swap: 0<->1, 2<->3..."""
    t = bytearray(b)
    for i in range(0, len(t) - 1, 2):
        t[i], t[i + 1] = t[i + 1], t[i]
    return bytes(t)


def block_pair_swap_bytes(b: bytes) -> bytes:
    """4-byte block pair swap: ABCD -> CDAB."""
    t = bytearray(b)
    n = len(t) - len(t) % 4
    for i in range(0, n, 4):
        t[i], t[i + 2] = t[i + 2], t[i]
        t[i + 1], t[i + 3] = t[i + 3], t[i + 1]
    return bytes(t)


_c5_keys_cache: Optional[Dict[str, Any]] = None

def get_c5_key(marker: str):
    global _c5_keys_cache
    if _c5_keys_cache is None:
        c5_path = _ENGINE_DIR / 'happcrypt5.json'
        if not c5_path.exists():
            c5_path = _ENGINE_DIR.parent / 'happcrypt5.json'
        if c5_path.exists():
            with open(c5_path, 'r', encoding='utf-8') as f:
                _c5_keys_cache = json.load(f)
        else:
            _c5_keys_cache = {}

    if marker not in _c5_keys_cache:
        return None
    raw_b64 = _c5_keys_cache[marker]
    der = base64.b64decode(raw_b64)
    return serialization.load_der_private_key(der, password=None)


def _crypt5_body(body: bytes, key, salted: bool) -> Optional[str]:
    if len(body) < 13:
        return None
    nonce = body[:12]
    salt = None
    pos = 12
    if salted:
        if len(body) < 22:
            return None
        salt = body[14:22]
        pos = 22
    start = pos
    while pos < len(body) and 48 <= body[pos] <= 57:
        pos += 1
    if pos == start:
        return None
    try:
        seg_len = int(body[start:pos].decode('ascii'))
    except Exception:
        return None

    packed = body[pos:]
    if not packed or seg_len > len(packed) - 1:
        return None
    url_b64 = packed[1:seg_len + 1].decode('utf-8', errors='replace')
    enc_b64 = packed[seg_len + 1:].decode('utf-8', errors='replace')

    enc_bytes = base64.b64decode(enc_b64 + '=' * ((-len(enc_b64)) % 4))
    rsa_plain = key.decrypt(enc_bytes, padding.PKCS1v15())
    key_material_b64 = swap_pairs_bytes(rsa_plain).decode('latin-1')
    key_material = base64.b64decode(key_material_b64 + '=' * ((-len(key_material_b64)) % 4))
    if len(key_material) != 32:
        return None

    if salt:
        km = bytearray(key_material)
        for i in range(32):
            km[i] ^= salt[i % len(salt)]
        key_material = bytes(km)

    ct = base64.b64decode(url_b64 + '=' * ((-len(url_b64)) % 4))
    text = None
    for aead in (ChaCha20Poly1305(key_material), AESGCM(key_material)):
        try:
            text = aead.decrypt(nonce, ct, None)
            break
        except Exception:
            pass
    if text is None:
        return None

    plain_b64 = swap_pairs_bytes(text).decode('latin-1')
    return base64.b64decode(plain_b64 + '=' * ((-len(plain_b64)) % 4)).decode('utf-8', errors='replace')


def decrypt_happ_crypt5(payload: str) -> Optional[str]:
    """Decrypt happ://crypt5/ payload with marker routing and candidate fallback."""
    payload = payload.strip()
    for pref in ('happ://crypt5/', 'crypt5/', 'happ://'):
        if payload.startswith(pref):
            payload = payload[len(pref):]
            break
    payload = payload.strip()

    base = payload.rstrip('=')
    candidates = [base]
    if len(base) > 10:
        candidates.append(base[:-2])
    if base != payload:
        candidates.append(payload)
    candidates = list(dict.fromkeys(candidates))

    for cand in candidates:
        n = block_pair_swap_bytes(cand.encode('utf-8', errors='ignore'))
        if len(n) < 8:
            continue
        marker = (n[:4] + n[-4:]).decode('latin-1', errors='ignore')
        body = n[4:-4]

        key = get_c5_key(marker)
        if not key:
            continue

        salted_auto = len(body) > 12 and not (48 <= body[12] <= 57)
        for salted in (salted_auto, not salted_auto):
            try:
                res = _crypt5_body(body, key, salted)
                if res:
                    return res
            except Exception:
                pass
    return None


# ============================================================================
# INCY VPN DECRYPTOR (incy://crypt1/...)
# ============================================================================

_incy_keys_cache: Optional[Dict[str, bytes]] = None

def get_incy_key(scheme: str = 'crypt1') -> Optional[bytes]:
    global _incy_keys_cache
    if _incy_keys_cache is None:
        _incy_keys_cache = {}
        incy_path = _ENGINE_DIR / 'incy.json'
        if not incy_path.exists():
            incy_path = _ENGINE_DIR.parent / 'incy.json'
        if incy_path.exists():
            try:
                with open(incy_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for s_name, cfg in data.get('schemes', {}).items():
                    if 'key' in cfg and cfg['key'].strip():
                        _incy_keys_cache[s_name.lower()] = base64.b64decode(cfg['key'])
                    elif 'keymat_a' in cfg and 'keymat_b' in cfg:
                        a = base64.b64decode(''.join(cfg['keymat_a'].split()))
                        b = base64.b64decode(''.join(cfg['keymat_b'].split()))
                        off_a = cfg.get('keymat_a_offset', 1024)
                        off_b = cfg.get('keymat_b_offset', 2048)
                        klen = cfg.get('keymat_len', 32)
                        salt = ''.join(str(p) for p in (cfg.get('salt_parts') or ())).encode('utf-8')
                        _incy_keys_cache[s_name.lower()] = hashlib.sha256(
                            salt + a[off_a:off_a + klen] + b[off_b:off_b + klen]
                        ).digest()
            except Exception as e:
                logging.warning(f"Failed to load incy.json: {e}")

    return _incy_keys_cache.get(scheme.lower())


def decrypt_incy(link: str) -> Optional[str]:
    """Decrypt incy://crypt1/<payload> into destination sub URL."""
    clean = link.strip()
    m = re.match(r'(?i)^incy://(crypt[0-9]+)/(.+)$', clean)
    if not m:
        return None
    scheme = m.group(1).lower()
    payload = re.sub(r'[^A-Za-z0-9_\-]', '', m.group(2).rstrip('/'))
    if not payload:
        return None

    key = get_incy_key(scheme)
    if not key:
        return None

    try:
        wire = base64.urlsafe_b64decode(payload + '=' * ((-len(payload)) % 4))
        if len(wire) < 12 + 16 + 1:
            return None
        iv, ct_and_tag = wire[:12], wire[12:]
        plaintext = AESGCM(key).decrypt(iv, ct_and_tag, None)
        parsed = json.loads(plaintext.decode('utf-8'))
        url = parsed.get('url') if isinstance(parsed, dict) else None
        return url if isinstance(url, str) else None
    except Exception as e:
        logging.warning(f"INCY decrypt error: {e}")
        return None


# ============================================================================
# V2RAYTUN UNWRAPPER (v2raytun://import/...)
# ============================================================================

V2RAYTUN_TARGETS = (
    "http://", "https://", "vless://", "vmess://", "trojan://", "ss://",
    "hy2://", "hysteria2://", "happ://", "incy://", "wdtt://", "qwdtt://"
)

def unwrap_v2raytun_import(url: str, depth: int = 0) -> str:
    """Recursively unwraps v2raytun://import/<payload> into inner config or sub URL."""
    if not url.lower().startswith("v2raytun://import/"):
        return url
    rest = url[len("v2raytun://import/"):].strip()
    if rest.lower().startswith(V2RAYTUN_TARGETS):
        return rest
    try:
        cand = urllib.parse.unquote(rest)
    except Exception:
        cand = rest
    if cand.lower().startswith(V2RAYTUN_TARGETS):
        return cand

    cand_clean = re.sub(r'[^A-Za-z0-9+/=_\-]', '', cand)
    if len(cand_clean) >= 8:
        for alt in (None, '-_'):
            try:
                pad = '=' * ((-len(cand_clean)) % 4)
                dec = base64.b64decode(cand_clean + pad, altchars=alt).decode('utf-8', errors='ignore').strip()
                if dec.lower().startswith("v2raytun://import/") and depth < 6:
                    return unwrap_v2raytun_import(dec, depth + 1)
                if dec.lower().startswith(V2RAYTUN_TARGETS):
                    return dec
            except Exception:
                pass
    return url
