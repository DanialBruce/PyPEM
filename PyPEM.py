'''Copyright 2022 Danial Mousavi (DanialBruce)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.'''


# source code for getting cert chain PEM part: https://stackoverflow.com/questions/51039393/get-or-build-pem-certificate-chain-in-python


from OpenSSL import SSL, crypto
import socket

##format = False
def start():
  format = False
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

    
# This functions gets the PEM data and stores it in the same. 
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
    for cert in peerCertChain: 
        pemFile += newLineFormatter(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    return pemFile

  for cert in peerCertChain:
      pemFile += crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")

  return pemFile


def newLineFormatter(string = ''):

  result = ''
  strLines = string.split('\n')

  for line in strLines:
    if line == '':
      continue
    result += '\"' + line +'\\n\"' + '\n'
  
  return result



def storePEMfile(data, hostname, port):
  with open(hostname + str(port) + '_pem.PEM', 'w') as f:
    f.write(data)


if __name__ == '__main__':
  start()