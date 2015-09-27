import os, string

oldWin = '''span {
	font-family: Verdana;
	background: #e0e0d0;
	font-size: 10pt;
}
</style>
</head>
<body bgcolor="#e0e0d0">
'''

oldLinux = '''span {
	font-family: Verdana;
	background: #e0e0d0;
	font-size: 13pt;
}
</style>
</head>
<body bgcolor="#e0e0d0">
'''

new = '''span {
	font-family: Verdana;
}
</style>
</head>
<body bgcolor="#f0f0f8">
'''

def fixhtmlfile(file):
    if os.path.isfile(file) and file[-5:] == '.html':
        print file
        fp = open(file, 'rt')
        cont = fp.read()
        fp.close()
        cont = string.replace(cont, '\r\n', '\n')
        cont = string.replace(cont, oldWin, new)
        cont = string.replace(cont, oldLinux, new)
        fp = open(file, 'wt')
        fp.write(cont)
        fp.close()

def fixhtmlfiles(dir):
    files = os.listdir(dir)
    for file in files:
        fixhtmlfile(dir + os.sep + file)
