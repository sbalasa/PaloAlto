import requests
import requests_mock

@requests_mock.Mocker()
def test_palo_alto(m=None):
    url = "https://10.88.88.80"
    _headers = {"X-PAN-KEY": "24fsddfsrea", "Content-Type": "application/json"}
    m.put(
        f"{url}/restapi/9.0/Policies/SecurityPostRules",
        headers=_headers,
        text="success"
    )
    return requests.put(
        f"{url}/restapi/9.0/Policies/SecurityPostRules",
        headers=_headers,
    ).text

print(test_palo_alto())
