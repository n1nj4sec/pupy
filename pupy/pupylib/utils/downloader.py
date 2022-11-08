#!/usr/bin/env python
# -*- coding: UTF8 -*-

import requests
import shutil
from tqdm.auto import tqdm

def download(url, to):
    with requests.get(url, stream=True) as r:
        print(r)
        print(dir(r))
        total_length = int(r.headers.get("Content-Length"))
        with tqdm.wrapattr(r.raw, "read", total=total_length, desc="")as raw:
            with open(to, 'wb')as output:
                shutil.copyfileobj(raw, output)
