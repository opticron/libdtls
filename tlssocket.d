module tlssocket;
import std.socket;
import std.stdio;
import libdtls.gnutls;
/// This TcpSocket derivative acts just like a socket, except it's using TLS x509 encryption.
/// Select probably doesn't work. Technically, it's possible to rework this to be able to use services supporting starttls.
class TlsSocket:TcpSocket {
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
	const int MAX_BUF = 1024;
	char * CAFILE = "ca.pem";
	/// Constructor requiring a host and port.  This constructor creates an InternetAddress and calls the other constructor.
	this(string host, ushort port = 25) {
		this(new InternetAddress(host, port));
	}
	/// Take care of pre-connection TLS stuff
	private void tls_pre_connect() {
		int ret;
		char*err;
		gnutls_global_init ();
		
		// X509 stuff
		gnutls_certificate_allocate_credentials (&xcred);
		
		// sets the trusted certificate authority file
		gnutls_certificate_set_x509_trust_file (xcred, CAFILE, GNUTLS_X509_FMT_PEM);
		
		// Initialize TLS session 
		gnutls_init (&session, GNUTLS_CLIENT);
		
		// Use default priorities
		ret = gnutls_priority_set_direct (session, "PERFORMANCE", &err);
		if (ret < 0) {
		    if (ret == GNUTLS_E_INVALID_REQUEST) {
		        throw new Exception("Syntax error at: "~std.string.toString(err));
		    }
		    throw new Exception("TLS Error: returned with "~std.string.toString(ret));
		}
		
		// put the x509 credentials to the current session
		gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
	}
	/// Take care of TLS handshake
	private void tls_post_connect() {
		int ret;
		// lob the socket handle off to gnutls
		gnutls_transport_set_ptr (session, cast(gnutls_transport_ptr_t) handle);

		// Perform the TLS handshake
		ret = gnutls_handshake (session);
		if (ret < 0) {
			throw new Exception("Handshake failed: "~std.string.toString(gnutls_strerror(ret)));
		}
		// Handshake completed
	}
	/// Non-autoconnecting constructor
	override this() {
		tls_pre_connect();
	}
	/// Constructor requiring an InternetAddress.
	/// This constructor sets up GNUTLS, opens the socket, and hands the socket to GNUTLS for handshaking.
	/// When the constructor returns, the encrypted connection is open and ready for use.
	override this(Address ia) {
		tls_pre_connect();
		// create the connection
		super(ia);
		tls_post_connect();
	}
	/// Connection for non-auto-connect instantiation
	override void connect(Address ia) {
		super.connect(ia);
		tls_post_connect();
	}
	/// Close the encrypted connection.
	override void close() {
		gnutls_bye (session, GNUTLS_SHUT_RDWR);
		super.close;
		gnutls_deinit(session);
		gnutls_certificate_free_credentials(xcred);
		gnutls_global_deinit();
	}
	/// Send data over the encrypted connection.
	override int send(void[]toSend) {
		return gnutls_record_send (session, toSend.ptr, toSend.length);
	}
	/// Receive data over the encrypted connection.  This function emulates the standard socket.receive operation.
	override int receive(void[]buffer) {
		return gnutls_record_recv(session,cast(void*)buffer.ptr,buffer.length);
	}
	/// Grab data from the encrypted connection.  This operation is blocking.
	/// Return: Any available data.  A zero-length string means the connection has been closed.
	string getData() {
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
	const string MSG = "GET / HTTP/1.0\r\n\r\n\0";
	// connect to a host and start up tls
	auto sock = new TlsSocket(new InternetAddress("zimbra.digium.com",443));
	
	// make sure the socket gets closed and TLS turned off on exit
	scope(exit) {
	      sock.close();
	}
	
	// send our message!
	sock.send(MSG);
	// read in the response (a HTML page in this case)
	string output = sock.getData;
	// houston, we have html (if we've made it this far)
	writefln("Got output from zimbra: %s",output);
	return 0;
}

