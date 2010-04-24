module clientconnection;
import std.socket;
import std.stdio;
import gnutls;
class TLSClientConnection {
	Socket socket;
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
	const int MAX_BUF = 1024;
	char * CAFILE = "ca.pem";
	/// Constructor requiring an InternetAddress.  This constructor sets up GNUTLS, opens the socket, and hands the socket to GNUTLS for handshaking.  When the constructor returns, the encrypted connection is open and ready for use.
	this(InternetAddress ia) {
		int ret;
		char*err;
		gnutls_global_init ();
		
		/* X509 stuff */
		gnutls_certificate_allocate_credentials (&xcred);
		
		// sets the trusted certificate authority file
		gnutls_certificate_set_x509_trust_file (xcred, CAFILE, GNUTLS_X509_FMT_PEM);
		
		// Initialize TLS session 
		gnutls_init (&session, GNUTLS_CLIENT);
		
		/* Use default priorities */
		ret = gnutls_priority_set_direct (session, "PERFORMANCE", &err);
		if (ret < 0) {
		    if (ret == GNUTLS_E_INVALID_REQUEST) {
		        throw new Exception("Syntax error at: "~std.string.toString(err));
		    }
		    throw new Exception("TLS Error: returned with "~std.string.toString(ret));
		}
		
		/* put the x509 credentials to the current session
		 */
		gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
		// create the connection
		// XXX maybe fix this to use raw sockets....
		socket = new TcpSocket(ia);
		// lob the socket handle off to gnutls
		gnutls_transport_set_ptr (session, cast(gnutls_transport_ptr_t) socket.handle);

		// Perform the TLS handshake
		ret = gnutls_handshake (session);
		if (ret < 0) {
			throw new Exception("Handshake failed: "~std.string.toString(gnutls_strerror(ret)));
		}
		// Handshake completed
	}
	/// Close the encrypted connection.
	void close() {
		gnutls_bye (session, GNUTLS_SHUT_RDWR);
		socket.close;
		gnutls_deinit(session);
		gnutls_certificate_free_credentials(xcred);
		gnutls_global_deinit();
	}
	/// Send data over the encrypted connection.
	void send(string toSend) {
		gnutls_record_send (session, MSG.ptr, MSG.length);
	}
	/// Grab data from the encrypted connection.  This operation is blocking.
	/// Return: Any available data.  A zero-length string means the connection has been closed.
	string receive() {
		int ret;
  		char buffer[MAX_BUF];
		string output = null;
		do {
			ret = gnutls_record_recv (session, cast(void*)buffer, MAX_BUF);
			if (ret > 0) {
				// received ret bytes
				output ~= buffer[0..ret];
			} else if (ret == 0) {
				// return zero-length string since the connection is closed
				return "";
			} else if (ret < 0) {
				throw new Exception("TLS Error: "~std.string.toString(gnutls_strerror(ret)));
			}
			
		} while (ret==MAX_BUF);
		return output;
	}
}


unittest {
	string MSG = "GET / HTTP/1.0\r\n\r\n\0";
	// connect to a host and start up tls
	auto sock = new TLSClientConnection(new InternetAddress("mail.google.com",443));
	
	// make sure the socket gets closed and TLS turned off on exit
	scope(exit) {
	      sock.close();
	}
	
	// send our message!
	sock.send(MSG);
	// read in the response (a HTML page in this case)
	string output = sock.receive;
	// houston, we have html (if we've made it this far)
	writefln("Got output from gmail: %s",output);
	return 0;
}
