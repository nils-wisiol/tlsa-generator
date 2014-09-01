// init express framework
var express = require('express');
var app = express();

// promises
var Q = require('q');

// certificate handling
var cert = require('./cert');

// start server
var server = app.listen(3000, function() {
	console.log('Listening on port %d', server.address().port);
});

// function to report problems to the client
// this follows https://tools.ietf.org/html/draft-nottingham-http-problem-05
function problem(res, information) {
	res.set({
		'Content-Type': 'application/problem+json',
		'Content-Language': 'en',
	});
	res.status(403);
	res.send(information);
	return;
}

app.get('/convert/:domain/:port', function(req, res){
	// TODO sanitize domain and port
	var domain = req.params.domain;
	var port = req.params.port;
	
	cert.retrieve(domain, port)
		.then(function(pem) {
			cert.tlsa(pem).then(function(hash) {
				res.set({'Content-Type': 'text/plain'});
				res.send({
					dnssec: false,
					verified: false,
					domain: domain,
					port: port,
					hashes: hash,
					tsla: '_' + port + '._tcp.' + domain + '. IN TLSA 3 0 1 ' + hash,
					configuration: {
						certificateUsage: '3 - end entity',
						selector: '0 - full certificate',
						match: '1 - sha256'
					},
					pem: pem
				});
			});
		});
});
