import BaseHTTPServer, SimpleHTTPServer
import ssl

if __name__ == '__main__':
  httpd = BaseHTTPServer.HTTPServer(
      ('localhost', 4443),
      SimpleHTTPServer.SimpleHTTPRequestHandler)

  cert = "c:\\Coding\\Python27\\Lib\\site-packages\\twisted\\test\\server.pem"
  #cert = '/usr/lib/python2.7/dist-packages/twisted/test/server.pem'

  httpd.socket = ssl.wrap_socket(httpd.socket,
      certfile=cert,
      server_side=True)
  httpd.serve_forever()
