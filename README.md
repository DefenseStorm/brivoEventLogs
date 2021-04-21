Brivo Integration for DefenseStorm

to pull this repository and submodules:

git clone --recurse-submodules https://github.com/DefenseStorm/brivoEventLogs.git

1. If this is the first integration on this DVM, Do the following:

  cp ds-integration/ds_events.conf to /etc/syslog-ng/conf.d

  Edit /etc/syslog-ng/syslog-ng.conf and add local7 to the excluded list for filter f_syslog3 and filter f_messages. The lines should look like the following:

filter f_syslog3 { not facility(auth, authpriv, mail, local7) and not filter(f_debug); };

filter f_messages { level(info,notice,warn) and not facility(auth,authpriv,cron,daemon,mail,news,local7); };


  Restart syslog-ng
    service syslog-ng restart

2. Copy the template config file and update the settings

  cp brivoEventLogs.conf.template brivoEventLogs.conf

  Configure the following in brivoEventLogs.conf based on Brivo API usage documentation at https://apidocs.brivo.com/

	username
	password
	api_key
	client_id
	client_secret




3. Add the following entry to the root crontab so the script will run every
   5 minutes

   */5 * * * * cd /usr/local/brivoEventLogs; ./brivoEventLogs.py
