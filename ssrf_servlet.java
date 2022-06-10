/**
 * $Id: ProxyServlet.java,v 1.4 2013/12/13 13:18:11 david Exp $
 * Copyright (c) 2011-2012, JGraph Ltd
 */

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Base64;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.nio.charset.StandardCharsets;

@SuppressWarnings("serial")
public class ProxyServlet extends HttpServlet
{
	private static final Logger log = Logger
			.getLogger(HttpServlet.class.getName());

	/**
	 * Buffer size for content pass-through.
	 */
	private static int BUFFER_SIZE = 3 * 1024;
	
	/**
	 * GAE deadline is 30 secs so timeout before that to avoid
	 * HardDeadlineExceeded errors.
	 */
	private static final int TIMEOUT = 29000;
	
	/**
	 * A resuable empty byte array instance.
	 */
	private static byte[] emptyBytes = new byte[0];

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public ProxyServlet()
	{
		super();
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException
	{
		String urlParam = request.getParameter("url");

		if (checkUrlParameter(urlParam))
		{
			// build the UML source from the compressed request parameter
			String ref = request.getHeader("referer");
			String ua = request.getHeader("User-Agent");
			String auth = request.getHeader("Authorization");
			String dom = getCorsDomain(ref, ua);

			try(OutputStream out = response.getOutputStream())
			{
				request.setCharacterEncoding("UTF-8");
				response.setCharacterEncoding("UTF-8");

				URL url = new URL(urlParam);
				URLConnection connection = url.openConnection();
				connection.setConnectTimeout(TIMEOUT);
				connection.setReadTimeout(TIMEOUT);
				
				response.setHeader("Cache-Control", "private, max-age=86400");

				// Workaround for 451 response from Iconfinder CDN
				connection.setRequestProperty("User-Agent", "draw.io");
				
				//Forward auth header
				if (auth  !=  null)
				{
					connection.setRequestProperty("Authorization", auth);
				}

				if (dom != null && dom.length() > 0)
				{
					response.addHeader("Access-Control-Allow-Origin", dom);
				}

				// Status code pass-through and follow redirects
				if (connection instanceof HttpURLConnection)
				{
					((HttpURLConnection) connection)
							.setInstanceFollowRedirects(true);
					int status = ((HttpURLConnection) connection)
							.getResponseCode();
					int counter = 0;

					// Follows a maximum of 6 redirects 
					while (counter++ <= 6
							&& (status == HttpURLConnection.HTTP_MOVED_PERM
									|| status == HttpURLConnection.HTTP_MOVED_TEMP))
					{
						url = new URL(connection.getHeaderField("Location"));
						connection = url.openConnection();
						((HttpURLConnection) connection)
								.setInstanceFollowRedirects(true);
						connection.setConnectTimeout(TIMEOUT);
						connection.setReadTimeout(TIMEOUT);

						// Workaround for 451 response from Iconfinder CDN
						connection.setRequestProperty("User-Agent", "draw.io");
						status = ((HttpURLConnection) connection)
								.getResponseCode();
					}

					if (status >= 200 && status <= 299)
					{
						response.setStatus(status);
						
						// Copies input stream to output stream
						InputStream is = connection.getInputStream();
						byte[] head = (contentAlwaysAllowed(urlParam)) ? emptyBytes
								: checkStreamContent(is);
						response.setContentType("application/octet-stream");
						String base64 = request.getParameter("base64");
						copyResponse(is, out, head,
								base64 != null && base64.equals("1"));
					}
					else
					{
						response.setStatus(HttpURLConnection.HTTP_PRECON_FAILED);
					}
				}
				else
				{
					response.setStatus(HttpURLConnection.HTTP_UNSUPPORTED_TYPE);
				}

				out.flush();

				log.log(Level.FINEST, "processed proxy request: url="
						+ ((urlParam != null) ? urlParam : "[null]")
						+ ", referer=" + ((ref != null) ? ref : "[null]")
						+ ", user agent=" + ((ua != null) ? ua : "[null]"));
			}
			catch (UnknownHostException | FileNotFoundException e)
			{
				// do not log 404 and DNS errors
				response.setStatus(HttpServletResponse.SC_NOT_FOUND);
			}
			catch (UnsupportedContentException e)
			{
				response.setStatus(HttpServletResponse.SC_FORBIDDEN);
				log.log(Level.SEVERE, "proxy request with invalid content: url="
						+ ((urlParam != null) ? urlParam : "[null]")
						+ ", referer=" + ((ref != null) ? ref : "[null]")
						+ ", user agent=" + ((ua != null) ? ua : "[null]"));
			}
			catch (Exception e)
			{
				response.setStatus(
						HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				log.log(Level.FINE, "proxy request failed: url="
						+ ((urlParam != null) ? urlParam : "[null]")
						+ ", referer=" + ((ref != null) ? ref : "[null]")
						+ ", user agent=" + ((ua != null) ? ua : "[null]"));
				e.printStackTrace();
			}
		}
		else
		{
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			log.log(Level.SEVERE,
					"proxy request with invalid URL parameter: url="
							+ ((urlParam != null) ? urlParam : "[null]"));
		}
	}

	/**
	 * Dynamically generated CORS header for known domains.
	 * @throws IOException 
	 */
	protected void copyResponse(InputStream is, OutputStream out, byte[] head,
			boolean base64) throws IOException
	{
		if (base64)
		{
			try (BufferedInputStream in = new BufferedInputStream(is,
					BUFFER_SIZE))
			{
				ByteArrayOutputStream os = new ByteArrayOutputStream();
			    byte[] buffer = new byte[0xFFFF];

				os.write(head, 0, head.length);
				
			    for (int len = is.read(buffer); len != -1; len = is.read(buffer))
			    { 
			        os.write(buffer, 0, len);
			    }

  				String s = new String(os.toByteArray(), StandardCharsets.UTF_8);
				out.write(s.getBytes());
			}
		}
		else
		{
			out.write(head);
			copy(is, out);
		}
	}

	/**
	 * Checks if the URL parameter is legal.
	 */
	public boolean checkUrlParameter(String url)
	{
		return url != null
				&& (url.startsWith("http://") || url.startsWith("https://"))
				&& !url.toLowerCase().contains("metadata.google.internal")
				&& !url.toLowerCase().contains("169.254.169.254");
	}

	/**
	 * Returns true if the content check should be omitted.
	 */
	public boolean contentAlwaysAllowed(String url)
	{
		return url.toLowerCase()
				.startsWith("https://trello-attachments.s3.amazonaws.com/")
				|| url.toLowerCase().startsWith("https://docs.google.com/");
	}

	/**
	 * Gets CORS header for request. Returning null means do not respond.
	 */
	protected String getCorsDomain(String referer, String userAgent)
	{
		String dom = null;

		if (referer != null && referer.toLowerCase()
				.matches("https?://([a-z0-9,-]+[.])*draw[.]io/.*"))
		{
			dom = referer.toLowerCase().substring(0,
					referer.indexOf(".draw.io/") + 8);
		}
		else if (referer != null && referer.toLowerCase()
				.matches("https?://([a-z0-9,-]+[.])*diagrams[.]net/.*"))
		{
			dom = referer.toLowerCase().substring(0,
					referer.indexOf(".diagrams.net/") + 13);
		}
		else if (referer != null && referer.toLowerCase()
				.matches("https?://([a-z0-9,-]+[.])*quipelements[.]com/.*"))
		{
			dom = referer.toLowerCase().substring(0,
					referer.indexOf(".quipelements.com/") + 17);
		}
		// Enables Confluence/Jira proxy via referer or hardcoded user-agent (for old versions)
		// UA refers to old FF on macOS so low risk and fixes requests from existing servers
		else if ((referer != null
				&& referer.equals("draw.io Proxy Confluence Server"))
				|| (userAgent != null && userAgent.equals(
						"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:50.0) Gecko/20100101 Firefox/50.0")))
		{
			dom = "";
		}

		return dom;
	}
	/**
	 *
	 */
	public static class UnsupportedContentException extends Exception
	{
		private static final long serialVersionUID = 1239597891574347740L;
	}

	private static SecureRandom randomSecure = new SecureRandom();
	
	/**
	 * 
	 */
	public static String CHARSET_FOR_URL_ENCODING = "ISO-8859-1";

	/**
	 * 
	 */
	protected static final int IO_BUFFER_SIZE = 4 * 1024;

	/**
	 * Alphabet for global unique IDs.
	 */
	public static final String TOKEN_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";

	/**
	 * Returns a random string of the given length.
	 */
	public static String generateToken(int length)
	{
		StringBuffer rtn = new StringBuffer();

		for (int i = 0; i < length; i++)
		{
			int offset = randomSecure.nextInt(TOKEN_ALPHABET.length());
			rtn.append(TOKEN_ALPHABET.substring(offset,offset+1));
		}

		return rtn.toString();
	};

	/**
	 * Applies a standard inflate algo to the input byte array
	 * @param binary the byte array to inflate
	 * @return the inflated String
	 * 
	 */
	public static String inflate(byte[] binary) throws IOException
	{
		StringBuffer result = new StringBuffer();
		InputStream in = new InflaterInputStream(
				new ByteArrayInputStream(binary), new Inflater(true));

		while (in.available() != 0)
		{
			byte[] buffer = new byte[IO_BUFFER_SIZE];
			int len = in.read(buffer, 0, IO_BUFFER_SIZE);

			if (len <= 0)
			{
				break;
			}

			result.append(new String(buffer, 0, len));
		}

		in.close();

		return result.toString();
	}

	/**
	 * Applies a standard deflate algo to the input String
	 * @param inString the String to deflate
	 * @return the deflated byte array
	 * 
	 */
	public static byte[] deflate(String inString) throws IOException
	{
		Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
		byte[] inBytes = inString.getBytes("UTF-8");
		deflater.setInput(inBytes);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream(
				inBytes.length);
		deflater.finish();
		byte[] buffer = new byte[IO_BUFFER_SIZE];

		while (!deflater.finished())
		{
			int count = deflater.deflate(buffer); // returns the generated code... index  
			outputStream.write(buffer, 0, count);
		}

		outputStream.close();
		byte[] output = outputStream.toByteArray();

		return output;
	}

	/**
	 * Copies the input stream to the output stream using the default buffer size
	 * @param in the input stream
	 * @param out the output stream
	 * @throws IOException
	 */
	public static void copy(InputStream in, OutputStream out) throws IOException
	{
		copy(in, out, IO_BUFFER_SIZE);
	}

	/**
	 * Copies the input stream to the output stream using the specified buffer size
	 * @param in the input stream
	 * @param out the output stream
	 * @param bufferSize the buffer size to use when copying
	 * @throws IOException
	 */
	public static void copy(InputStream in, OutputStream out, int bufferSize)
			throws IOException
	{
		byte[] b = new byte[bufferSize];
		int read;

		while ((read = in.read(b)) != -1)
		{
			out.write(b, 0, read);
		}
	}

	/**
	 * Reads an input stream and returns the result as a String
	 * @param stream the input stream to read
	 * @return a String representation of the input stream
	 * @throws IOException
	 */
	public static String readInputStream(InputStream stream) throws IOException
	{
		BufferedReader reader = new BufferedReader(
				new InputStreamReader(stream));
		StringBuffer result = new StringBuffer();
		String tmp = reader.readLine();

		while (tmp != null)
		{
			result.append(tmp + "\n");
			tmp = reader.readLine();
		}

		reader.close();

		return result.toString();
	}

	/**
	  * Encodes the passed String as UTF-8 using an algorithm that's compatible
	  * with JavaScript's <code>encodeURIComponent</code> function. Returns
	  * <code>null</code> if the String is <code>null</code>.
	  * 
	  * @param s The String to be encoded
	  * @param charset the character set to base the encoding on
	  * @return the encoded String
	  */
	public static String encodeURIComponent(String s, String charset)
	{
		if (s == null)
		{
			return null;
		}
		else
		{
			String result;

			try
			{
				result = URLEncoder.encode(s, charset).replaceAll("\\+", "%20")
						.replaceAll("\\%21", "!").replaceAll("\\%27", "'")
						.replaceAll("\\%28", "(").replaceAll("\\%29", ")")
						.replaceAll("\\%7E", "~");
			}
			catch (UnsupportedEncodingException e)
			{
				// This exception should never occur
				result = s;
			}

			return result;
		}
	}

	/**
	 * Checks the file type of an input stream and returns the
	 * bytes that have been read (because URL connections to not
	 * have support for mark/reset).
	 */
	static public byte[] checkStreamContent(InputStream is)
			throws IOException, UnsupportedContentException
	{
		byte[] head = new byte[16];
		boolean valid = false;

		if (is.read(head) == head.length)
		{
			int c1 = head[0] & 0xFF;
			int c2 = head[1] & 0xFF;
			int c3 = head[2] & 0xFF;
			int c4 = head[3] & 0xFF;
			int c5 = head[4] & 0xFF;
			int c6 = head[5] & 0xFF;
			int c7 = head[6] & 0xFF;
			int c8 = head[7] & 0xFF;
			int c9 = head[8] & 0xFF;
			int c10 = head[9] & 0xFF;
			int c11 = head[10] & 0xFF;
			int c12 = head[11] & 0xFF;
			int c13 = head[12] & 0xFF;
			int c14 = head[13] & 0xFF;
			int c15 = head[14] & 0xFF;
			int c16 = head[15] & 0xFF;

			if (c1 == '<')
			{
				// text/html
				if (c2 == '!'
						|| ((c2 == 'h'
								&& (c3 == 't' && c4 == 'm' && c5 == 'l'
										|| c3 == 'e' && c4 == 'a' && c5 == 'd')
								|| (c2 == 'b' && c3 == 'o' && c4 == 'd'
										&& c5 == 'y')))
						|| ((c2 == 'H'
								&& (c3 == 'T' && c4 == 'M' && c5 == 'L'
										|| c3 == 'E' && c4 == 'A' && c5 == 'D')
								|| (c2 == 'B' && c3 == 'O' && c4 == 'D'
										&& c5 == 'Y'))))
				{
					valid = true;
				}

				// application/xml
				if (c2 == '?' && c3 == 'x' && c4 == 'm' && c5 == 'l'
						&& c6 == ' ')
				{
					valid = true;
				}
				
				// application/svg+xml
				if (c2 == 's' && c3 == 'v' && c4 == 'g' && c5 == ' ')
				{
					valid = true;
				}
			}

			// big and little (identical) endian UTF-8 encodings, with BOM
			// application/xml
			if (c1 == 0xef && c2 == 0xbb && c3 == 0xbf)
			{
				if (c4 == '<' && c5 == '?' && c6 == 'x')
				{
					valid = true;
				}
			}

			// big and little endian UTF-16 encodings, with byte order mark
			// application/xml
			if (c1 == 0xfe && c2 == 0xff)
			{
				if (c3 == 0 && c4 == '<' && c5 == 0 && c6 == '?' && c7 == 0
						&& c8 == 'x')
				{
					valid = true;
				}
			}

			// application/xml
			if (c1 == 0xff && c2 == 0xfe)
			{
				if (c3 == '<' && c4 == 0 && c5 == '?' && c6 == 0 && c7 == 'x'
						&& c8 == 0)
				{
					valid = true;
				}
			}

			// big and little endian UTF-32 encodings, with BOM
			// application/xml
			if (c1 == 0x00 && c2 == 0x00 && c3 == 0xfe && c4 == 0xff)
			{
				if (c5 == 0 && c6 == 0 && c7 == 0 && c8 == '<' && c9 == 0
						&& c10 == 0 && c11 == 0 && c12 == '?' && c13 == 0
						&& c14 == 0 && c15 == 0 && c16 == 'x')
				{
					valid = true;
				}
			}

			// application/xml
			if (c1 == 0xff && c2 == 0xfe && c3 == 0x00 && c4 == 0x00)
			{
				if (c5 == '<' && c6 == 0 && c7 == 0 && c8 == 0 && c9 == '?'
						&& c10 == 0 && c11 == 0 && c12 == 0 && c13 == 'x'
						&& c14 == 0 && c15 == 0 && c16 == 0)
				{
					valid = true;
				}
			}

			// image/gif
			if (c1 == 'G' && c2 == 'I' && c3 == 'F' && c4 == '8')
			{
				valid = true;
			}

			// image/x-bitmap
			if (c1 == '#' && c2 == 'd' && c3 == 'e' && c4 == 'f')
			{
				valid = true;
			}

			// image/x-pixmap
			if (c1 == '!' && c2 == ' ' && c3 == 'X' && c4 == 'P' && c5 == 'M'
					&& c6 == '2')
			{
				valid = true;
			}

			// image/png
			if (c1 == 137 && c2 == 80 && c3 == 78 && c4 == 71 && c5 == 13
					&& c6 == 10 && c7 == 26 && c8 == 10)
			{
				valid = true;
			}

			// image/jpeg
			if (c1 == 0xFF && c2 == 0xD8 && c3 == 0xFF)
			{
				if (c4 == 0xE0 || c4 == 0xEE)
				{
					valid = true;
				}

				/**
				 * File format used by digital cameras to store images.
				 * Exif Format can be read by any application supporting
				 * JPEG. Exif Spec can be found at:
				 * http://www.pima.net/standards/it10/PIMA15740/Exif_2-1.PDF
				 */
				if ((c4 == 0xE1) && (c7 == 'E' && c8 == 'x' && c9 == 'i'
						&& c10 == 'f' && c11 == 0))
				{
					valid = true;
				}
			}
			if (c1 == 0x00 && c2 == 0x01 && c3 == 0x00 && c4 == 0x00
					&& c5 == 0x00)
			{
				valid = true;
			}

			// otf
			if (c1 == 0x4F && c2 == 0x54 && c3 == 0x54 && c4 == 0x4F
					&& c5 == 0x00)
			{
				valid = true;
			}

			// woff
			if (c1 == 0x77 && c2 == 0x4F && c3 == 0x46 && c4 == 0x46)
			{
				valid = true;
			}

			// woff2
			if (c1 == 0x77 && c2 == 0x4F && c3 == 0x46 && c4 == 0x32)
			{
				valid = true;
			}

			// vsdx, vssx (also zip, jar, odt, ods, odp, docx, xlsx, pptx, apk, aar)
			if (c1 == 0x50 && c2 == 0x4B && c3 == 0x03 && c4 == 0x04)
			{
				valid = true;
			}
			else if (c1 == 0x50 && c2 == 0x4B && c3 == 0x03 && c4 == 0x06)
			{
				valid = true;
			}

			// vsd, ppt
			if (c1 == 0xD0 && c2 == 0xCF && c3 == 0x11 && c4 == 0xE0
					&& c5 == 0xA1 && c6 == 0xB1 && c7 == 0x1A && c8 == 0xE1)
			{
				valid = true;
			}

			// mxfile, mxlibrary, mxGraphModel
			if (c1 == '<' && c2 == 'm' && c3 == 'x')
			{
				valid = true;
			}

			if (c1 == '<' && c2 == 'D' && c3 == 'O' && c4 == 'C' && c5 == 'T'
					&& c6 == 'Y' && c7 == 'P' && c8 == 'E')
			{
				valid = true;
			}

			if (c1 == '<' && c2 == '!' && c3 == '-' && c4 == '-' && c5 == '['
					&& c6 == 'i' && c7 == 'f' && c8 == ' ')
			{
				valid = true;
			}

			// Gliffy
			if (c1 == '{' && c2 == '"' && c3 == 'c' && c4 == 'o' && c5 == 'n'
					&& c6 == 't' && c7 == 'e' && c8 == 'n' && c9 == 't'
					&& c10 == 'T' && c11 == 'y' && c12 == 'p' && c13 == 'e'
					&& c14 == '"' && c15 == ':')
			{
				valid = true;
			}

			// Lucidchart
			if (c1 == '{' && c2 == '"' && c3 == 's' && c4 == 't' && c5 == 'a'
					&& c6 == 't' && c7 == 'e' && c8 == '"' && c9 == ':')
			{
				valid = true;
			}
		}

		if (!valid)
		{
			throw new UnsupportedContentException();
		}

		return head;
	}

	public static boolean isNumeric (String str)
	{ 
		try
		{  
			Double.parseDouble(str);  
			return true;
		}
		catch(NumberFormatException e)
		{  
			return false;  
		}  
	}

}
