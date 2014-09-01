// execute child processes
var exec = require('child_process').exec;
var Q = require('q');

/**
 * Retrieve the certificate used for SSL connections at domain:port.
 * 
 * @param domain Hostname of the server to be contacted.
 * @param port Port of the server to be contacted.
 * @returns {promise|Q.promise} A promise eventually turning into the certificate (PEM format), or reject on error.
 */
function retrieve(domain, port) {
	var deferred = Q.defer();

	// TODO use DNSSEC to verify retrieved information
	// Use OpenSSL to retrieve certificate from server
	var retriever = exec('openssl s_client -connect ' + domain + ':' + port);

	var retrieverOutput = '';
	var certificatePEM = '';
	retriever.stdout.on('data', function(chunk) {
		// collect output
		retrieverOutput += chunk;
	})
	retriever.stdout.on('end', function() {
		// output complete, extract certificate
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

/**
 * Generate TLSA records out of a certificate (PEM format). Currently, the DANE
 * configuration used is 3 0 1:
 * - certificate usage: end entity
 * - selector: full certificate (that is, the fingerprint thereof)
 * - match: SHA256
 * 
 * @param cert The certificate (PEM format).
 * @param domain The domain the TSLA record is for
 * @param port The port the TSLA record is for
 * @returns {promise|Q.promise} A promise eventually turning into the hash
 */
function tlsa(cert, domain, port) {
	var deferred = Q.defer();

	// Use OpenSSL to generate the hashed fingerprint
	var hasher = exec('openssl x509 -fingerprint -sha256 -noout');

	var hasherOutput = '';
	hasher.stdout.on('data', function(chunk) {
		// collect output
		hasherOutput += chunk;
	});
	hasher.stdout.on('end', function() {
		// Output of OpenSSL complete
		try {
			var hash = hasherOutput.replace(/:/g, '').match(/^SHA256 Fingerprint=([A-Z0-9]{64})[\s\S]$/)[1];
			deferred.resolve('_' + port + '._tcp.' + domain + '. IN TLSA 3 0 1 ' + hash);
		} catch (e) {
			deferred.resolve('');
		}
	});

	// send cert to OpenSSL
	hasher.stdin.write(cert);
	hasher.stdin.end();

	return deferred.promise;
}

// Export public function
module.exports = {
	retrieve: retrieve,
	tlsa: tlsa
}
