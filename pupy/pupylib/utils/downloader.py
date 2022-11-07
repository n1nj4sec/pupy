#!/usr/bin/env python
# -*- coding: UTF8 -*-

import requests
import shutil
import os
from tqdm.auto import tqdm
# make an HTTP request within a context manager
with requests.get("https://www.example.com/file.txt", stream=True) as r:
    # check header to get content length, in bytes
    total_length = int(r.headers.get("Content-Length"))
    # implement progress bar via tqdm
    with tqdm.wrapattr(r.raw, "read", total=total_length, desc="")as raw:
        # save the output to a file
        with open(f"{os.path.basename(r.url)}", 'wb')as output:
            shutil.copyfileobj(raw, output)
