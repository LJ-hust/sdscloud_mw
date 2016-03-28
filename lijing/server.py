import os
from paste import httpserver
from paste.deploy import loadapp

if __name__ == '__main__':
    config = '/home/lj/my_libcloud/WSGI/proxy-server.conf'
    appname = 'main'
    global_conf = {}
    wsgi_app = loadapp('config:%s'%os.path.abspath(config),appname)
    httpserver.server_runner(wsgi_app,global_conf)

