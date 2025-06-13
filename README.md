# GHL OAuth Application

A secure, read-only OAuth application for GoHighLevel (GHL) that ensures existing CRM data remains protected and untouched.

## Data Protection Rules

1. Existing data is strictly read-only
2. No updates or modifications to existing records
3. No overwriting of existing data
4. New data additions must be done in a way that doesn't affect existing records
5. All operations are logged for audit purposes

## Features

- Console-based OAuth authentication
- Comprehensive connectivity checks
- Automatic token refresh
- Detailed error handling and logging
- Protection against data modification
- Audit logging of all operations

## Prerequisites

- Python 3.7 or higher
- pip (Python package manager)
- GoHighLevel API credentials

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ghl_oauth_app.git
cd ghl_oauth_app
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the project root with your GHL credentials:
```env
GHL_CLIENT_ID=your_client_id
GHL_CLIENT_SECRET=your_client_secret
GHL_REDIRECT_URI=http://localhost:8000/callback
```

## Usage

1. Run the application:
```bash
python app.py
```

2. Follow the on-screen instructions to complete the OAuth authentication process.

3. The application will automatically:
   - Check connectivity to GHL services
   - Handle token refresh
   - Maintain audit logs
   - Protect existing data

## Security Features

- Read-only access to CRM data
- No modification of existing records
- Comprehensive audit logging
- Secure token storage
- Automatic token refresh
- Connection security checks

## Project Structure

```
ghl_oauth_app/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── .env               # Environment variables (not in repo)
├── tokens.json        # OAuth tokens (not in repo)
├── data_operations.log # Audit logs (not in repo)
└── README.md          # This file
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

Please report any security issues to [your-email@example.com]

## Acknowledgments

- GoHighLevel API documentation
- Python requests library
- Python-dotenv 