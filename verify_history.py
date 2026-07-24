import app

client = app.app.test_client()
resp = client.get('/history')
print(resp.status_code)
print(resp.get_data(as_text=True)[:2000])
