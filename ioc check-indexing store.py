import os
import requests
import json
from flask import Flask, request, render_template

app = Flask(__name__)

# Index to store the IOCs and their categories
ioc_index = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the API key and the URL of the MISP server
        api_key = request.form.get('api_key')
        misp_url = request.form.get('misp_url')

        # Call the MISP API to get the events
        headers = {
            'Authorization': f'{api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        response = requests.get(f'{misp_url}/events', headers=headers)

        # Check if the API call was successful
        if response.status_code == 200:
            # Parse the response data and store it in a list
            events = response.json()['response']

            # Filter the events to get the relevant IOCs
            for event in events:
                for attribute in event['Attribute']:
                    if attribute['type'] in ['ip-dst', 'ip-src', 'domain', 'md5', 'sha1', 'sha256']:
                        ioc = attribute['value']
                        category = attribute['type']

                        # Store the IOC in the index
                        if ioc not in ioc_index:
                            ioc_index[ioc] = [category]
                        else:
                            ioc_index[ioc].append(category)

            # Return the results to the UI
            return render_template('index.html', ioc_index=ioc_index)
        else:
            # Return an error message to the UI
            return render_template('index.html', error='Failed to fetch events from the MISP server')
    else:
        return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
