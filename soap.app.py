from flask import Flask, request, jsonify, Response
from zeep import Client

app = Flask(__name__)


# SOAP servisini çağırmak için Zeep istemcisi
@app.route('/soap', methods=['POST'])
def soap_api():
    # Zeep istemcisi ile WSDL URL'sini belirtiyoruz
    wsdl_url = 'http://www.dneonline.com/calculator.asmx?WSDL'
    client = Client(wsdl_url)

    # SOAP servisine parametre gönderip yanıt alıyoruz
    try:
        # Örnek işlem: 5 + 10
        result = client.service.Add(5, 10)

        # SOAP yanıtı oluşturuyoruz
        response_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://www.dneonline.com">
           <soapenv:Header/>
           <soapenv:Body>
              <web:AddResponse>
                 <web:AddResult>{result}</web:AddResult>
              </web:AddResponse>
           </soapenv:Body>
        </soapenv:Envelope>"""

        return Response(response_xml, content_type="text/xml")

    except Exception as e:
        return f"Error: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5005)
