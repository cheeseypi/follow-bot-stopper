const Express = require('express')
const { createHmac, sign } = require('crypto')
const https = require('https')
const fs = require('fs')

var serverConfiguration = JSON.parse(fs.readFileSync('configuration.json'))

var callbackServer = Express();
callbackServer.use(Express.json({
    verify: (req, res, buf, encoding) => {
        let hmac = req.headers['twitch-eventsub-message-id'] + req.headers['twitch-eventsub-message-timestamp'] + buf.toString(encoding);
        let signature = 'sha256=' + createHmac('sha256', serverConfiguration.hmac_secret).update(hmac).digest('hex')
        if (req.headers['twitch-eventsub-message-signature'] != signature) {
            res.status(403).send("That's not a valid signature");
            console.error("INVALID TWITCH SIGNATURE RECEIVED");
            return false;
        }
    }
}));

callbackServer.post('/hooks/cb', (req, res) => {
    if(req.headers['twitch-eventsub-message-type'] == 'webhook_callback_verification')
        res.send(req.body.challenge)
    else
        console.log(req.headers['twitch-eventsub-message-type'], req.body)
        res.status(200).send()
})

callbackServer.listen(serverConfiguration.port, serverConfiguration.host, () => {
    console.log(`listening on http://${serverConfiguration.host}:${serverConfiguration.port}`);

    let authOptions = {
        hostname: serverConfiguration.twitch_auth_hostname,
        port: 443,
        method: 'POST',
        path: serverConfiguration.twitch_auth_path + `?client_id=${serverConfiguration.twitch_client_id}&client_secret=${serverConfiguration.twitch_client_secret}&grant_type=client_credentials`
    }
    let authReq = https.request(authOptions, res => {
        console.log("TWITCH AUTH REPLY:", res.statusCode)
        res.on('data', d => {
            let data = JSON.parse(new TextDecoder().decode(d))
            let subscriptionBody = {
                "type": "channel.follow",
                "version": "1",
                "condition": {
                    "broadcaster_user_id": serverConfiguration.twitch_target_uid
                },
                "transport": {
                    "method": "webhook",
                    "callback": "https://c4ea-100-1-88-71.ngrok.io/hooks/cb",
                    "secret": serverConfiguration.hmac_secret
                }
            }
            let subscriptionBodyEncoded = new TextEncoder().encode(JSON.stringify(subscriptionBody));
            let subscriptionOptions = {
                hostname: serverConfiguration.twitch_eventsub_hostname,
                port: 443,
                path: serverConfiguration.twitch_eventsub_path,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': subscriptionBodyEncoded.length,
                    'Client-ID': serverConfiguration.twitch_client_id,
                    'Authorization': 'Bearer ' + data.access_token
                }
            }
            let subReq = https.request(subscriptionOptions, res => {
                console.log('GOT TWITCH REPLY:', res.statusCode)
                res.on('data', d => {
                    console.log(new TextDecoder().decode(d))
                })
            })
            subReq.on('error', err => {
                console.log(err)
            })
            subReq.write(subscriptionBodyEncoded)
            subReq.end()
        })
    })
    authReq.write(new TextEncoder().encode(''))
    authReq.end()

})