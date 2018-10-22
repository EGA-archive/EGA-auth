#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
####################################
#
# Decrypting file from the vault, given a stable ID.
#
# Only used for testing to see if the encrypted file can be sent as a Crypt4GH-formatted stream
#
####################################
'''

import sys
import logging
from logging.config import dictConfig
import ssl
from pathlib import Path
import asyncio
from urllib.parse import urlencode
import yaml
import base64

from cryptography import fernet
from aiohttp import web, ClientSession
from aiohttp_session import get_session, setup as session_setup
from aiohttp_session.cookie_storage import EncryptedCookieStorage
import async_timeout
import aiohttp_jinja2
import jinja2

LOG = logging.getLogger('ega-relay')

import sqlite3
conn = sqlite3.connect('/run/ega.db')
conn.isolation_level = None # for autocommit

BASE_URL = 'http://tf.crg.eu:9090'

CLIENT_ID='lega'
CLIENT_SECRET='FEc4f9be0F2A9e0EaEd63775eAC1bab8A0dD16d7727C4eABe54FDE3fbabc511C'
SCOPE='profile email'

ACCESS_TOKEN_URL = 'https://idp.ega-archive.org/token'
USER_INFO_URL = 'https://idp.ega-archive.org/userinfo'

EGA_UID_SHIFT = 10000

####################################
async def _request(method, url, **kwargs):
    """Make a request through AIOHTTP."""
    timeout = kwargs.pop('timeout', None)
    try:
        async with async_timeout.timeout(timeout):
            async with ClientSession() as session:
                LOG.debug('%4s Request: %s', method, url)
                LOG.debug('Request Args: %s', kwargs)
                async with session.request(method, url, **kwargs) as response:
                    LOG.debug('Response type: %s', response.headers.get('CONTENT-TYPE'))
                    LOG.debug('Response: %s', response)
                    if response.status > 200:
                        raise web.HTTPBadRequest(reason=f'HTTP status code: {response.status}')
                    if 'json' in response.headers.get('CONTENT-TYPE'):
                        data = await response.json()
                    else:
                        data = await response.text()
                        data = dict(parse_qsl(data))
                    return data
    except asyncio.TimeoutError:
        raise web.HTTPBadRequest(reason='HTTP timeout')
    except Exception as e:
        LOG.debug('Exception: %s', e)
        return None


@aiohttp_jinja2.template('index.html')
async def index(request):

    LOG.debug('Getting session')
    session = await get_session(request)
    access_token = session.get('access_token')
    if not access_token:
        raise web.HTTPBadRequest(reason="Invalid credentials")
    LOG.debug('Token: %s', access_token)

    # Use template now
    return { 'user': session.get('user'), 'access_token': access_token }

async def oauth(request):
    code = request.query.get('code')
    if code is None:
        LOG.debug('We must have a code')
        raise web.BadRequest(reason="Should have a code")

    session_id = request.query.get('state')
    if not session_id:
        LOG.debug('We must have a state')
        raise web.BadRequest(reason="Should have a state")

    headers = { 'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' }

    # We have a code and a state
    LOG.debug('Code: %s', code)
    params = urlencode({ 'grant_type': 'authorization_code',
                         'client_id': CLIENT_ID,
                         'client_secret': CLIENT_SECRET,
                         'code': code,
                         'redirect_uri': BASE_URL })
    res = await _request('POST', ACCESS_TOKEN_URL, headers=headers, data=params)
    LOG.debug( 'Post Response %r', res)
    access_token = res.get('access_token') if res else None
    if not access_token: 
        LOG.error( 'Error when getting the access token: %r', res)
        raise web.HTTPBadRequest(reason='Failed to obtain OAuth access token.')
    LOG.debug('All good, we got an access token: %s', access_token)
    session = await get_session(request)
    session['access_token'] = access_token
    id_token = res.get('id_token')
    if id_token:
        LOG.debug('And an ID token? %s', id_token)
        session['id_token'] = id_token

    # Fetch more info about the user
    user = await _request('GET',
                          USER_INFO_URL + '?' + urlencode({'access_token': access_token}),
                          headers=headers)
    if not user:
        raise web.HTTPBadRequest(text='Invalid Request')
    LOG.info('The user is: %r', user)
    session['user'] = user

    # Adding to database
    cur = conn.cursor()

    username = user.get('nickname')
    uid = EGA_UID_SHIFT + int(user.get('sub', '-1'))
    gecos = user.get('gecos', 'Local EGA User')
    LOG.debug('User info')
    LOG.debug('\tUsername: %s', username)
    LOG.debug('\tUID: %d', uid)
    LOG.debug('\tGecos: %s', gecos)
    LOG.debug('\tsession_id: %s', session_id)
    LOG.debug('\taccess_token: %s', access_token)
    LOG.debug('\tid_token: %s', id_token)

    # User first
    cur.execute('INSERT INTO users (username,uid,gecos) VALUES(?1,?2,?3);', [username, uid, gecos])
    #conn.commit()

    # Token last
    cur.execute('INSERT INTO tokens (user,session_id,access_token,id_token) VALUES(?1,?2,?3,?4);',
                [uid, session_id, access_token, (id_token or '')])
    #conn.commit()
    cur.close()
    raise web.HTTPFound(location=request.app.router['index'].url_for())

def main(args=None):
    if not args:
        args = sys.argv[1:]

    here = Path(__file__).parent.resolve()
    with open(here / 'logger.yaml', 'r') as stream:
        dictConfig(yaml.load(stream))

    host = '0.0.0.0'
    port = 9001
    sslcontext = None

    #loop = asyncio.get_event_loop()
    #loop.set_debug(True)
    server = web.Application()
    server.router.add_get( '/'       , index, name='index')
    server.router.add_get( '/tokens/', oauth)

    # Where the templates are
    template_loader = jinja2.FileSystemLoader(str(here))
    aiohttp_jinja2.setup(server, loader=template_loader)

    # Session middleware
    fernet_key = fernet.Fernet.generate_key()
    secret_key = base64.urlsafe_b64decode(fernet_key) # 32 url-safe base64-encoded bytes
    session_setup(server, EncryptedCookieStorage(secret_key))

    # ...and cue music
    LOG.info(f"Start outgest server on {host}:{port}")
    web.run_app(server, host=host, port=port, shutdown_timeout=0, ssl_context=sslcontext)


if __name__ == '__main__':
    main()


