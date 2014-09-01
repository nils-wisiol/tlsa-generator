// execute child processes
var exec = require('child_process').exec;
var Q = require('q');

function retrieve(domain, port) {
	var deferred = Q.defer();

	// TODO use DNSSEC to verify retrieved information
	var retriever = exec('openssl s_client -connect ' + domain + ':' + port);

	var retrieverOutput = '';
	var certificatePEM = '';
	retriever.stdout.on('data', function(chunk) {
		retrieverOutput += chunk;
	})
	retriever.stdout.on('end', function() {
		// extract certificate
		try {
			certificatePEM = retrieverOutput.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9\s\S/=]+-----END CERTIFICATE-----/)[0];
			deferred.resolve(certificatePEM);
		} catch (e) {
			deferred.reject();
		}
	});

	// send dummy HTTP request to comply with HTTP standard
	retriever.stdin.write('OPTIONS / HTTP/1.1\nHost: ' + domain + '\n');
	retriever.stdin.end(); // close pipe to cause openssl to exit
	
	return deferred.promise;
}

function tlsa(cert) {
	var deferred = Q.defer();

	var hasher = exec('openssl x509 -fingerprint -sha256 -noout');

	var hasherOutput = '';
	hasher.stdout.on('data', function(chunk) {
		hasherOutput += chunk;
	});
	hasher.stdout.on('end', function() {
		try {
			deferred.resolve(hasherOutput.replace(/:/g, '').match(/^SHA256 Fingerprint=([A-Z0-9]{64})[\s\S]$/)[1]);
		} catch (e) {
			deferred.resolve('');
		}
	});

	hasher.stdin.write(cert);
	hasher.stdin.end();

	return deferred.promise;
}

// Export public function
module.exports = {
	retrieve: retrieve,
	tlsa: tlsa
}
