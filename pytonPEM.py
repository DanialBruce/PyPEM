# source code for getting cert chain PEM part: https://stackoverflow.com/questions/51039393/get-or-build-pem-certificate-chain-in-python


from OpenSSL import SSL, crypto
import socket

def start():
  hostname = input("the remost host domain name or ip address: ")
  while True:
    try:
        port = int(input("enter port number: "))
    except ValueError:
      print("<!-- Type a port number! -->")
      continue
    else:
      break
  
  while True:
    usr = input("Do you want to add  \"\" and \\n to each lines of PEM file for ease of use in your code? (Y/n)").lower().strip()
    print(usr)
    if usr not in ('','y','yes','n', 'no'):
      continue
    break

  if usr in ('y', ''):
    format = True
  
  try:
    storePEMfile(getPEMFile(hostname, port, format), hostname, port)
  except Exception as e:
    print(f"Exception!!: {e}")
  
  print("Operation complete!")
  input("Press Enter to exit the program . . .")

    

def getPEMFile(hostname, port, nl_format = False):

  dst = (hostname, port)
  ctx = SSL.Context(SSL.TLSv1_2_METHOD)
  s = socket.create_connection(dst)
  s = SSL.Connection(ctx, s)
  s.set_connect_state()
  s.set_tlsext_host_name(str.encode(dst[0]))

  s.sendall(str.encode('HEAD / HTTP/1.0\n\n'))

  peerCertChain = s.get_peer_cert_chain()
  pemFile = ''

  if nl_format:
    num = 1
    for cert in peerCertChain: 
      if num != len(peerCertChain): #If it is the last item in the list
        pemFile += newLineFormatter(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        num += 1
      else:
        pemFile += newLineFormatter(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"), True)
    return pemFile
  
  
  for cert in peerCertChain:
      pemFile += crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")

  return pemFile


def newLineFormatter(string = '', last_item = False):

  final = ''
  strLines = string.split('\n')

  num = 1
  if last == False:
    for line in strLines:
      num += 1
      final += '\"' + line +'\\n\"' + '\n'
  else:
    for line in strLines:
      if num != len(strLines):  #If it is the last item in the list
        final += '\"' + line +'\\n\"' + '\n'
        num += 1
      else:
        final += '\"' + line +'\"'  + '\n'
  
  return final



def storePEMfile(data, hostname, port):
  with open(hostname + str(port) + '_pem.PEM', 'w') as f:
    f.write(data)


if __name__ == '__main__':
  start()