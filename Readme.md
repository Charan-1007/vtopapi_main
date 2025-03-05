# VTOP API 🚀

A Node.js-based API service to programmatically retrieve academic data from VIT University's VTOP portal using web scraping techniques.

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
![Axios](https://img.shields.io/badge/Axios-5A29E4?style=for-the-badge&logo=axios&logoColor=white)

---

## Features ✨

- Automated student authentication with VTOP credentials
- Built-in CAPTCHA solving system
- Comprehensive academic data retrieval:
  - Student Profile Information
  - Attendance Records (Overview & Detailed)
  - Course Timetable
  - Academic Marks/Grades
  - Grade History & CGPA
  - Exam Schedules
  - Digital Assignments
  - Fee Receipts
- Rate limiting for API protection
- CORS enabled for cross-origin requests
- Security headers with Helmet.js

---

## Prerequisites 📋

- Node.js (v14 or higher)
- NPM or Yarn package manager
- 1GB+ RAM
- Stable internet connection

---

## Installation & Usage 🛠️

1. **Clone repository**
```bash
git clone https://github.com/Charan-1007/vtopapi_main.git
cd vtopapi_main
 ```
```

2. Install dependencies
```bash
npm install
 ```

3. Start the server
```bash
npm start
 ```

The server will start on port 3000 by default or use the PORT environment variable.

## API Endpoints 🌐
### 1. Initial Data
```http
POST /initialdata
Content-Type: application/json

{
    "username": "your_registration_number",
    "password": "your_password"
}
 ```
```

### 2. Semester Data
```http
POST /semesterdata
Content-Type: application/json

{
    "username": "your_registration_number",
    "password": "your_password",
    "semesterId": "VL20242501"
}
 ```
```

## Response Structure 📦
```json
{
  "status": "success",
  "data": {
    "semester": [...],
    "Attendance": [...],
    "Course": [...],
    "Marks": [...],
    "CGPA": {...},
    "ExamSchedule": [...]
  }
}
 ```

## Security Features 🔒
- Rate limiting (100 requests per 15 minutes)
- Helmet.js security headers
- CORS protection
- Cookie jar support for session management
- Secure credential handling
## Security & Disclaimer 🔒
⚠️ Important Notice:

- This project is not officially affiliated with VIT University.
- Use at your own risk - credentials are transmitted securely but depend on VTOP's security.
- API may break with VTOP portal updates.
- Never share your credentials with untrusted parties.
- Maintained for educational purposes only.
## Technical Details 🔧
### Dependencies
- express : Web framework
- axios : HTTP client
- cheerio : HTML parsing
- canvas : CAPTCHA processing
- tough-cookie : Cookie management
- helmet : Security headers
- cors : CORS support
- express-rate-limit : Rate limiting
### Key Features Implementation
- Custom CAPTCHA solver using image processing
- Concurrent request handling for detailed data
- Robust error handling and retry mechanisms
- Session management with cookie persistence
## Contributing 🤝
Contributions are welcome! Please:

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
