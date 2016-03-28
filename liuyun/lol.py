import logging

class Lol(object):
    def __init__(self,conf):
        pass

    def __call__(self,env,start_response=None):
        if start_response is not None:
            start_response('200 OK',[('Content-Type','text/html')])
        logger = logging.getLogger('lollogger')
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler('test.log')
        fh.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s-%(name)s-%(levelname)s-%(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

        logger.info("LOL is really fantastic!")
        return ['LOL is really fantastic\n']

def app_factory(global_config, **local_conf):
    conf = global_config.copy()
    conf.update(local_conf)
    return Lol(conf)
