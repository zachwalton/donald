#!/usr/bin/python2.6
"""
donald

	This is an IRC bot that dumps Twitter updates to a channel.
	For now, it only supports joining one channel.
	
	donald is based loosely on Mike Verdone's Python Twitter
	Tools ircbot.py and the Twisted Words IRC example. Forgive
	inefficiencies or long-winded code; this is my first Twisted
	application (and I'm not much of a Python expert, either).

USAGE

	donald [configfile]

CONFIGFILE

	This is a JSON document with the bot's configuration options.
	If no argument is specified on the command line, use donald.conf.
	See donald.conf.example for a template. There is no warning
	upon startup if something's missing, so try and get it right.

DEPENDENCIES

	twitter - Mike Verdone's Python Twitter Tools
	twisted - Twisted (including Twisted Words)

"""


from twisted.words.protocols import irc
from twisted.internet import reactor, protocol
from twisted.python import log


import urllib2
from twitter.api import Twitter, TwitterError, TwitterHTTPError
from twitter.oauth import OAuth, read_token_file
import twitter
import twitter.oauth_dance
from dateutil.parser import parse
from htmlentitydefs import name2codepoint
import simplejson as json


import os, time, sys, re


CODE_BOLD = chr(0x02)

def htmlentitydecode(s):
	return re.sub('&(%s);' % '|'.join(name2codepoint), 
		lambda m: unichr(name2codepoint[m.group(1)]), s)


def sanitize_tweet_text(text):
	return htmlentitydecode(text.replace('\n', ' '))


class TwitterState(object):
	user = None
	CONSUMER_KEY = 'JUsaK5vMXismwD6g323HWg'
	CONSUMER_SECRET = 'EKGSxMLzuGKaKwL30oxFVAukQN2S2QvBs2Q5hb1Ch0'            

	def __init__(self, config):
		if not config['twitter']['oauth_key'] or not config['twitter']['oauth_secret']: key, secret = self._oauth_init(self.CONSUMER_KEY, self.CONSUMER_SECRET, config)
		else:
			key = config['twitter']['oauth_key']
			secret = config['twitter']['oauth_secret']
		self.twitter = Twitter(auth=OAuth(key,secret,self.CONSUMER_KEY,self.CONSUMER_SECRET))
		self.interval = config['twitter']['interval']
		reactor.callInThread(self._get_my_info)

	def _get_my_info(self):
		# retrieve our own user information from the twitter server
		try:
			self.user = self.twitter.account.verify_credentials()
		except (TwitterError, TwitterHTTPError, urllib2.URLError):
			log.err()
	
	def _oauth_init(self, key, secret, config):
		#setup oauth key if it doesn't exist, dump to filename
		twitterConnect = twitter.Twitter(auth=twitter.oauth.OAuth('','',key,secret),api_version=None,format='')
		oauth_token, oauth_token_secret = twitter.oauth_dance.parse_oauth_tokens(twitterConnect.oauth.request_token())
		print "To allow access to your Twitter account, please visit the following URL and click 'Accept':\r\nhttp://api.twitter.com/oauth/authorize?oauth_token=%s" % oauth_token
		oauth_token_pin = input("Enter PIN: ")
		twitterConnect = twitter.Twitter(auth=twitter.oauth.OAuth(oauth_token,oauth_token_secret,key,secret),api_version=None,format='')
		oauth_token, oauth_token_secret = twitter.oauth_dance.parse_oauth_tokens(twitterConnect.oauth.access_token(oauth_verifier=oauth_token_pin))
		config['twitter']['oauth_key']=oauth_token
		config['twitter']['oauth_secret']=oauth_token_secret
		#make the dump prettier, maybe with pprint.  also, pass filename in from __main__
		json.dump(config,'donald.conf')
		return oauth_token, oauth_token_secret

	def reset_state(self):
		"""Reset the state of the 'client.'"""
		# we want to make sure that we only get tweets that haven't been
		# seen before, so call this when the channel is joined or whatever
		self.since_id = None
		self.start_time = time.gmtime()

	def schedule_check(self, callback):
		self.callback = callback
		reactor.callLater(float(self.interval), reactor.callInThread, self._check_for_updates)

	def _check_for_updates(self):
		args = dict()
		if self.since_id != None:
			args['since_id'] = self.since_id

		new_updates = []

		try:
			updates = self.twitter.statuses.home_timeline(**args)
			if updates.count:
				if self.since_id == None:
					# if we haven't gotten any statuses yet, then we should
					# only deal with posts made after the bot was running
					for update in updates:
						tweet_time = parse(update['created_at']).utctimetuple()
						if tweet_time > self.start_time:
							new_updates.append(update)
							self.since_id = max(self.since_id, update['id'])
				else:
					# otherwise, just put 'em all in the queue
					for update in updates:
						new_updates.append(update)
						self.since_id = max(self.since_id, update['id'])
		# if the bot is set up properly, this just means twitter is sucking
		except (TwitterError, TwitterHTTPError, urllib2.URLError):
			log.err()

		# call the callback with our new stuff
		reactor.callFromThread(self.callback, new_updates)

	def tweet(self, message):
		reactor.callInThread(self._update_status, message)

	def _update_status(self, message):
		text = message.encode('utf-8', 'replace')
		self.twitter.statuses.update(status=text)

class TwitterBot(irc.IRCClient):
	"""Twitter IRC bot."""

	# set this (in seconds) to provide automatic flood control
	# this allows us to just fire off the tweet messages carelessly
	lineRate = 1

	# our defaults
	username = 'Lamest'
	nickname = 'LamestBot'
	realname = 'I\'m to lame to edit donald.conf'
	versionName = 'donald'
	versionNum = '0.1'

	enable_tweets = False

	def __init__(self, config):
		self.config = config

		self.username = self.config['irc']['username']
		self.nickname = self.config['irc']['nickname']
		self.realname = self.config['irc']['realname']

	def connectionMade(self):
		irc.IRCClient.connectionMade(self)
		self.twitter = TwitterState(self.config)

	def connectionLost(self, reason):
		self.enable_tweets = False
		irc.IRCClient.connectionLost(self, reason)

	def signedOn(self):
		log.msg('CONNECTED')
		self.join(self.config['irc']['channel'])

	def _schedule_tweet_check(self):
		self.twitter.schedule_check(self.on_tweets)

	def joined(self, channel):
		log.msg('JOIN %s' % (channel))
		# reset the state and start waiting on new tweets
		self.enable_tweets = True
		self.twitter.reset_state()
		self._schedule_tweet_check()

	def left(self, channel):
		log.msg('PART/KICK %s' % (channel))
		# we don't want to wastefully poll twitter if we're not even in the channel
		self.enable_tweets = False

	def on_tweets(self, tweets):
		# ignore this update, and stop getting tweets if we're turned off/kicked/dc'd
		if not self.enable_tweets:
			return

		for tweet in tweets:
			# respect the option to not display the bot's own tweets
			display_tweet = not self.config['options']['display_self_tweets'] and self.twitter.user and tweet['user']['screen_name'] != self.twitter.user['screen_name']
			if display_tweet:
				self.msg(self.config['irc']['channel'],
					'%s@%s:%s %s' % (CODE_BOLD, tweet['user']['screen_name'].encode('utf-8'),
					CODE_BOLD, sanitize_tweet_text(tweet['text']).encode('utf-8')))
		# schedule another check
		self._schedule_tweet_check()

	def privmsg(self, user, channel, msg):
		# check to see if this is a message sent to the bot
		if channel == self.nickname:
			self.handle_privmsg(user, msg)
			return

		# check to see if this is a message in a channel addressing the bot
		if msg.startswith(self.nickname + ": "):
			parts = msg.partition(': ')
			if parts[2] != '':
				self.handle_mention(channel, user, parts[2])

	def handle_privmsg(self, user, msg):
		log.msg('PRIVMSG: <%s> %s' % (user, msg))

	def handle_mention(self, channel, user, msg):
		nick = user.split('!', 1)[0]

		# post an update in the form "<nick> their message"
		if self.config['options']['allow_channel_tweets']:
			tweet = '<%s> %s' % (nick, msg)
			log.msg('TWEETING: %s' % (tweet))
			self.twitter.tweet(tweet)
		else:
			log.msg('MENTION: <%s> %s' % (nick, msg))

	def alterCollidedNick(self, nickname):
		# turn 'nickname' into 'nicknam0' ... 'nicknamF'
		if not self._nick_style:
			self._nick_count = 0

		nickname = '%s%X' % (nickname[:-1], self._nick_count)
		self._nick_count = self._nick_count + 1 if self._nick_count < 15 else 0

		return nickname


class TwitterBotFactory(protocol.ClientFactory):
    # the class of the protocol to build when new connection is made
	protocol = TwitterBot

	def __init__(self, config):
		self.config = config
		self.irc = self.protocol(config)

	def buildProtocol(self, addr=None):
		return self.irc

	def clientConnectionLost(self, connector, reason):
		"""Reconnect if disconnected."""
		log.msg('Disconnected. Reconnecting...')
		connector.connect()

	def clientConnectionFailed(self, connector, reason):
		"""Can't conect to the IRC server. Just bail."""
		log.msg('Connection failed: %s' % (reason))
		reactor.stop()


if __name__ == '__main__':
	config_filename = 'donald.conf'
	if sys.argv[1:]:
		config_filename = sys.argv[1]

	# i'd be nice and build in some defaults, but ehh
	config = dict()

	try:
		if not os.path.exists(config_filename):
			raise Exception()
		config = json.load(open(config_filename, 'r'))
	except Exception, e:
		print >> sys.stderr, "Couldn't load configuration file %s" % (config_filename)
		print >> sys.stderr, e
		print >> sys.stderr, __doc__
	
		sys.exit(1)
	log.startLogging(open(config['general']['logfilename'], 'a'))
	# we're good to go...	
	f = TwitterBotFactory(config)
	reactor.connectTCP(config['irc']['server'], config['irc']['port'], f)
	
	# run bot
	reactor.run()
