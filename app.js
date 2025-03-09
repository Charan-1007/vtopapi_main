const express = require('express');
const axios = require("axios");
const cheerio = require("cheerio");
const tough = require("tough-cookie");
const { wrapper } = require("axios-cookiejar-support");
const { solveCaptchaFromBase64 } = require("./captchasolver");
const fs = require('fs');
const readline = require('readline');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Security middlewares
app.use(helmet());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Existing middleware
app.use(bodyParser.json());

// User session cache for connection pooling
const userSessions = new Map();
const SESSION_TIMEOUT = 5 * 60 * 1000; // 30 minutes

// Get or create a client for a specific user
function getUserClient(username) {
    // Check if we have a valid session for this user
    if (userSessions.has(username)) {
        const session = userSessions.get(username);
        // Check if session is still valid (not expired)
        if (Date.now() - session.lastUsed < SESSION_TIMEOUT) {
            // Update last used timestamp
            session.lastUsed = Date.now();
            console.log(`Reusing existing session for user: ${username}`);
            return session.client;
        }
        // Session expired, remove it
        console.log(`Session expired for user: ${username}`);
        userSessions.delete(username);
    }
    
    // Create a new client for this user
    console.log(`Creating new session for user: ${username}`);
    const client = getNewClient();
    
    // Store the new session
    userSessions.set(username, {
        client: client,
        lastUsed: Date.now()
    });
    
    return client;
}

// Periodically clean up expired sessions
setInterval(() => {
    const now = Date.now();
    let expiredCount = 0;
    for (const [username, session] of userSessions.entries()) {
        if (now - session.lastUsed > SESSION_TIMEOUT) {
            userSessions.delete(username);
            expiredCount++;
        }
    }
    if (expiredCount > 0) {
        console.log(`Cleaned up ${expiredCount} expired sessions. Active sessions: ${userSessions.size}`);
    }
}, 5 * 60 * 1000); // Check every 5 minutes

// Create a function to get a new client with fresh cookies
function getNewClient() {
    const cookieJar = new tough.CookieJar();
    return wrapper(
        axios.create({
            jar: cookieJar,
            timeout: 10000,
            maxSockets: 50,
            keepAlive: true
        })
    );
}

const url =
  "https://vtop.vit.ac.in/vtop/prelogin/setup?_csrf=915d4b89-b5a2-4004-b733-bf07d64cc0f5&flag=VTOP";

// Function to detect CAPTCHA type
function detectCaptchaType($, html) {
  // Check for inbuilt CAPTCHA with prioritized selectors
  if (
    $("#captchaBlock").length ||
    $('img[alt="vtopCaptcha"]').length ||
    $(".form-control.img-fluid").length
  ) {
    return "inbuilt";
  }

  // Check JavaScript variable `captchaType`
  const captchaTypeMatch = html.match(/var\s+captchaType\s*=\s*(\d+);/);
  if (captchaTypeMatch && parseInt(captchaTypeMatch[1], 10) === 1) {
    return "inbuilt";
  }

  // Check for any base64 encoded images as fallback
  if (html.match(/data:image\/(jpeg|png|gif);base64,[^"]+/)) {
    return "inbuilt";
  }

  return "unknown";
}

// Function to extract CAPTCHA image from the response
function extractCaptchaImage($, html) {
  // Try to find the CAPTCHA image from various selectors
  const captchaImg =
    $('img[alt="vtopCaptcha"]').attr("src") ||
    $(".form-control.img-fluid").attr("src");

  if (captchaImg) return captchaImg;

  // Look for base64 encoded images in the HTML
  const base64Match = html.match(/data:image\/(jpeg|png|gif);base64,[^"]+/);
  if (base64Match) return base64Match[0];

  // If all methods fail, extract src from any img tag
  const anyImg = $("img").first().attr("src");
  if (anyImg && anyImg.includes("base64")) return anyImg;

  return null;
}

async function fetchWithSession(client) {
  try {
    const maxAttempts = 10;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      // Send GET request
      const response = await client.get(url, {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        },
      });

      // Load response HTML into Cheerio
      const $ = cheerio.load(response.data);

      // Detect CAPTCHA type
      const captchaType = detectCaptchaType($, response.data);

      // If inbuilt CAPTCHA is found, process it
      if (captchaType === "inbuilt") {
        // Extract CSRF token
        const csrfToken =
          $('input[name="_csrf"]').val() ||
          $('meta[name="_csrf"]').attr("content");

        // Extract the CAPTCHA image
        const captchaImage = extractCaptchaImage($, response.data);

        if (captchaImage && csrfToken) {
          // Solve the CAPTCHA
          const captchaSolution = await solveCaptchaFromBase64(captchaImage);

          if (captchaSolution) {
            return { csrf: csrfToken, captchaSolution };
          }
        }
      }

      // Add a small delay between attempts
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  } catch (error) {
    console.error("Error:", error.message);
  }

  return null;
}

// Function to check for error messages in response
function checkResponseForErrors(html) {
  if (!html) return null;

  // Check for invalid login/password message
  if (html.includes("Invalid LoginId/Password")) {
    return "credentials";
  }

  // Check for invalid captcha message
  if (html.includes("Invalid Captcha")) {
    return "captcha";
  }

  return null;
}

// Modify attemptLogin function
async function attemptLogin(username, password, client) {
    if (!client) {
        return { success: false, message: "No client provided" };
    }

    const maxAttempts = 5;
    let attempt = 0;

    while (attempt < maxAttempts) {
        attempt++;
        
        // Get CSRF and CAPTCHA solution
        const result = await fetchWithSession(client);
        if (!result || !result.csrf || !result.captchaSolution) {
            console.log("Failed to get CSRF token or solve CAPTCHA");
            continue;
        }

        try {
            const encodedUsername = encodeURIComponent(username);
            const encodedPassword = encodeURIComponent(password);
            const loginUrl = `https://vtop.vit.ac.in/vtop/login?_csrf=${result.csrf}&username=${encodedUsername}&password=${encodedPassword}&captchaStr=${result.captchaSolution}`;

            const loginResponse = await client.post(loginUrl, null, {
                headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
            });

            const errorType = checkResponseForErrors(loginResponse.data);
            if (errorType === "credentials") {
                return { success: false, message: "Invalid credentials" };
            } else if (errorType === "captcha") {
                console.log("Invalid CAPTCHA detected. Retrying...");
                continue;
            }

            return { success: true, data: loginResponse.data };
        } catch (error) {
            console.error("Login Error:", error.message);
        }
    }

    return { success: false, message: "Maximum login attempts reached" };
}

// Add this function to extract student ID
function extractStudentId(html) {
    const idMatch = html.match(/var\s+id\s*=\s*"([^"]+)"/);
    return idMatch ? idMatch[1] : null;
}

// Add this function to extract CGPA details
function extractCGPADetails(html) {
    try {
        const $ = cheerio.load(html);
        
        // Find the table with CGPA details (more specific selector)
        const cgpaRow = $('table.table-hover.table-bordered tbody tr');
        
        if (!cgpaRow.length) {
            console.log("CGPA details table not found");
            return null;
        }

        // Extract all cells from the row
        const cells = cgpaRow.find('td');

        // Create structured CGPA data
        const cgpaDetails = {
            creditsRegistered: parseFloat($(cells[0]).text().trim()) || 0,
            creditsEarned: parseFloat($(cells[1]).text().trim()) || 0,
            cgpa: parseFloat($(cells[2]).text().trim()) || 0,
            grades: {
                S: parseInt($(cells[3]).text().trim()) || 0,
                A: parseInt($(cells[4]).text().trim()) || 0,
                B: parseInt($(cells[5]).text().trim()) || 0,
                C: parseInt($(cells[6]).text().trim()) || 0,
                D: parseInt($(cells[7]).text().trim()) || 0,
                E: parseInt($(cells[8]).text().trim()) || 0,
                F: parseInt($(cells[9]).text().trim()) || 0,
                N: parseInt($(cells[10]).text().trim()) || 0
            }
        };

        // Validate data
        if (cgpaDetails.cgpa === 0 && cgpaDetails.creditsEarned === 0) {
            console.log("Warning: All values are zero, possible extraction error");
            return null;
        }

        return cgpaDetails;
    } catch (error) {
        console.error("Error extracting CGPA details:", error.message);
        return null;
    }
}

// Modify the fetchGradeHistory function
async function fetchGradeHistory(studentId, csrf, client) {
    try {
        const gradeUrl = `https://vtop.vit.ac.in/vtop/examinations/examGradeView/StudentGradeHistory?verifyMenu=true&authorizedID=${studentId}&_csrf=${csrf}&nocache=@(new Date().getTime())`;
        
        const response = await client.post(gradeUrl, null, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Extract CGPA details
        const cgpaDetails = extractCGPADetails(response.data);
        
        return cgpaDetails;
    } catch (error) {
        console.error("Error fetching grade history:", error.message);
        return null;
    }
}

// Add this function to fetch grade view
async function fetchGradeView(studentId, csrf, semesterSubId, client) {
    try {
        const gradeViewUrl = `https://vtop.vit.ac.in/vtop/examinations/examGradeView/doStudentGradeView`;
        
        const response = await client.post(gradeViewUrl, null, {
            params: {
                authorizedID: studentId,
                _csrf: csrf,
                semesterSubId: semesterSubId
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Just extract and return the data
        const gradeData = extractGradeView(response.data);
        return gradeData;
    } catch (error) {
        console.error("Error fetching grade view:", error.message);
        return null;
    }
}

// Function to extract grade view details
function extractGradeView(html) {
    try {
        const $ = cheerio.load(html);
        const courses = [];
        let gpa = null;

        // Find all course rows
        $('table.table-hover tr').each((index, row) => {
            // Skip header rows (first 2 rows)
            if (index < 2) return;

            const cells = $(row).find('td');
            
            // Check if this is the GPA row
            if ($(row).find('td[colspan]').length > 0) {
                gpa = parseFloat($(row).text().match(/GPA\s*:\s*(\d+\.\d+)/)?.[1]);
                return;
            }

            // Skip if not a regular course row
            if (cells.length !== 12) return;

            const course = {
                slNo: cells.eq(0).text().trim(),
                courseCode: cells.eq(1).text().trim(),
                courseTitle: cells.eq(2).text().trim(),
                courseType: cells.eq(3).text().trim(),
                credits: {
                    L: parseInt(cells.eq(4).text().trim()) || 0,
                    P: parseInt(cells.eq(5).text().trim()) || 0,
                    J: parseInt(cells.eq(6).text().trim()) || 0,
                    C: parseInt(cells.eq(7).text().trim()) || 0
                },
                gradingType: cells.eq(8).text().trim(),
                grandTotal: parseInt(cells.eq(9).text().trim()),
                grade: cells.eq(10).text().trim(),
                isNonGPACourse: $(row).css('background-color')?.includes('C0D8C0') || false
            };

            courses.push(course);
        });

        return {
            courses,
            gpa
        };
    } catch (error) {
        console.error("Error extracting grade view:", error.message);
        return null;
    }
}

// Modify the fetchGradeView function
async function fetchGradeView(studentId, csrf, semesterSubId, client) {
    try {
        const gradeViewUrl = `https://vtop.vit.ac.in/vtop/examinations/examGradeView/doStudentGradeView`;
        
        const response = await client.post(gradeViewUrl, null, {
            params: {
                authorizedID: studentId,
                _csrf: csrf,
                semesterSubId: semesterSubId
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Just extract and return the data
        const gradeData = extractGradeView(response.data);
        return gradeData;
    } catch (error) {
        console.error("Error fetching grade view:", error.message);
        return null;
    }
}

// Add this function to extract semester list
function extractSemesterList(html) {
    try {
        const $ = cheerio.load(html);
        const semesterSelect = $('#semesterSubId');
        
        if (!semesterSelect.length) {
            console.log("Semester select not found");
            return null;
        }

        // Extract all options except the first one (--Choose Semester--)
        const semesters = [];
        semesterSelect.find('option').each((index, element) => {
            const value = $(element).val();
            const text = $(element).text();
            
            // Skip the empty/default option
            if (value && value.trim() !== '') {
                semesters.push({
                    id: value,
                    name: text
                });
            }
        });

        return semesters;
    } catch (error) {
        console.error("Error extracting semester list:", error.message);
        return null;
    }
}

// Modify the fetchSemesterList function
async function fetchSemesterList(studentId, csrf, client) {
    try {
        const semesterListUrl = `https://vtop.vit.ac.in/vtop/academics/common/StudentTimeTable?verifyMenu=true&authorizedID=${studentId}&_csrf=${csrf}&nocache=@(new Date().getTime())`;
        
        const response = await client.post(semesterListUrl, null, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Extract semester list
        const semesterList = extractSemesterList(response.data);
        
        return semesterList;
    } catch (error) {
        console.error("Error fetching semester list:", error.message);
        return null;
    }
}

// Add the function to calculate GMT timestamp
function calculateGMTTimestamp() {
    const now = new Date();
    return now.toUTCString();
}

// Add function to get user input for semester
function getUserInput(prompt) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    return new Promise((resolve) => {
        rl.question(prompt, (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

// Function to extract timetable details
function extractTimeTable(html) {
    try {
        const $ = cheerio.load(html);
        const timetableData = {
            courses: [],
            totalCredits: ''
        };
        
        // Find the main table
        const table = $('table').first();
        
        // Extract courses data
        table.find('tr').each((index, row) => {
            // Skip header row and total credits row
            if (index === 0 || $(row).find('td[colspan]').length > 0) {
                // Extract total credits from the last row
                if ($(row).find('td[colspan]').length > 0) {
                    timetableData.totalCredits = $(row).find('span:last').text().trim();
                }
                return;
            }
            
            const cells = $(row).find('td');
            if (cells.length < 12) return;

            const courseDetails = {
                slNo: $(cells[0]).find('p').text().trim(),
                classGroup: $(cells[1]).find('p').text().trim(),
                course: {
                    name: $(cells[2]).find('p').first().text().trim().split(' - '),
                    type: $(cells[2]).find('p').last().text().trim().replace(/[()]/g, '').trim()
                },
                credits: $(cells[3]).find('p').text().trim(),
                category: $(cells[4]).find('span').text().trim(),
                courseOption: $(cells[5]).find('p').text().trim(),
                classId: $(cells[6]).find('p').text().trim(),
                slot: {
                    timing: $(cells[7]).find('p').first().text().trim().replace(' - ', ''),
                    venue: $(cells[7]).find('p').last().text().trim()
                },
                faculty: {
                    name: $(cells[8]).find('p').first().text().trim().replace(' - ', ''),
                    school: $(cells[8]).find('p').last().text().trim()
                },
                registrationDate: $(cells[9]).find('p').text().trim(),
                attendance: {
                    date: $(cells[10]).find('span').text().trim(),
                    type: $(cells[10]).find('strong').text().trim().replace(' - ', '')
                },
                status: $(cells[11]).find('span').text().trim()
            };

            // Split course name into code and name
            if (courseDetails.course.name.length === 2) {
                courseDetails.course = {
                    code: courseDetails.course.name[0],
                    name: courseDetails.course.name[1],
                    type: courseDetails.course.type
                };
            }

            timetableData.courses.push(courseDetails);
        });

        return timetableData;
    } catch (error) {
        console.error("Error extracting timetable:", error.message);
        return null;
    }
}

// Modify the fetchTimeTable function
async function fetchTimeTable(studentId, csrf, semesterId, client) {
    try {
        const timestamp = calculateGMTTimestamp();
        const timeTableUrl = `https://vtop.vit.ac.in/vtop/processViewTimeTable`;
        
        const response = await client.post(timeTableUrl, null, {
            params: {
                authorizedID: studentId,
                _csrf: csrf,
                semesterSubId: semesterId,
                x: encodeURIComponent(timestamp)
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        const timeTableData = extractTimeTable(response.data);
        return { timeTableData, semesterSubId: semesterId };
    } catch (error) {
        console.error("Error fetching timetable:", error.message);
        return null;
    }
}

// Function to extract attendance data
function extractAttendance(html) {
    try {
        const $ = cheerio.load(html);
        const attendanceData = {
            courses: []
        };

        // Process each row in the attendance table
        $('#AttendanceDetailDataTable tbody tr').each((index, row) => {
            const $row = $(row);
            const cells = $row.find('td');

            // Skip if not enough cells
            if (cells.length < 10) return;

            // Extract course ID and type from the onclick attribute
            const attendanceLink = $row.find('a[id^="studentAttendanceDetilShow"]');
            const onclickAttr = attendanceLink.attr('onclick') || '';
            const courseIdMatch = onclickAttr.match(/VL_[A-Z0-9]+_\d+/);
            const courseTypeMatch = onclickAttr.match(/,'([A-Z]+)'\);/);

            const course = {
                slNo: cells.eq(0).find('span').text().trim(),
                classGroup: cells.eq(1).find('span').text().trim(),
                courseDetail: cells.eq(2).find('span').text().trim(),
                classDetail: cells.eq(3).find('span').text().trim(),
                facultyDetail: cells.eq(4).find('span').text().trim(),
                attendedClasses: parseInt(cells.eq(5).find('span').text().trim()) || 0,
                totalClasses: parseInt(cells.eq(6).find('span').text().trim()) || 0,
                attendancePercentage: cells.eq(7).find('span span').text().trim(),
                debarStatus: cells.eq(8).text().trim().replace(/\s+/g, ' ').trim(),
                courseId: courseIdMatch ? courseIdMatch[0] : null,
                courseType: courseTypeMatch ? courseTypeMatch[1] : null
            };

            // Check for specific debar status information
            const debarInfo = cells.eq(8).find('span span');
            if (debarInfo.length > 0) {
                const examType = debarInfo.eq(0).text().trim();
                const status = debarInfo.eq(1).text().trim();
                course.debarStatus = {
                    examType: examType.replace(':', '').trim(),
                    status: status
                };
            }

            attendanceData.courses.push(course);
        });

        return attendanceData;
    } catch (error) {
        console.error("Error extracting attendance data:", error.message);
        return null;
    }
}

// Function to parse detailed attendance HTML
function parseDetailedAttendance($, html) {
    try {
        const attendanceDetails = {
            courseInfo: {},
            attendanceRecords: []
        };

        // Extract course information from the first table
        const courseInfo = $('#StudentCourseDetailDataTable tbody tr').first();
        if (courseInfo.length) {
            attendanceDetails.courseInfo = {
                classGroup: courseInfo.find('td:eq(0) span').text().trim(),
                courseDetail: courseInfo.find('td:eq(1) span').text().trim(),
                classDetail: courseInfo.find('td:eq(2) span').text().trim(),
                facultyDetail: courseInfo.find('td:eq(3) span').text().trim(),
                registeredDateTime: courseInfo.find('td:eq(4) span').text().trim(),
                attendanceSummary: {
                    present: parseInt(courseInfo.find('td:eq(6) span b:contains("Present") + span').text()) || 0,
                    absent: parseInt(courseInfo.find('td:eq(6) span b:contains("Absent") + span').text()) || 0,
                    onDuty: parseInt(courseInfo.find('td:eq(6) span b:contains("On Duty") + span').text()) || 0,
                    attended: parseInt(courseInfo.find('td:eq(6) span b:contains("Attended") + span').text()) || 0,
                    totalClasses: parseInt(courseInfo.find('td:eq(6) span b:contains("Total Class") + span').text()) || 0,
                    percentage: courseInfo.find('td:eq(6) span b:contains("Percentage") + span span').text().trim()
                }
            };
        }

        // Extract attendance records
        $('#StudentAttendanceDetailDataTable tbody tr').each((index, row) => {
            const $row = $(row);
            const record = {
                slNo: $row.find('td:eq(0) span').text().trim(),
                date: $row.find('td:eq(1) span').text().trim(),
                slot: $row.find('td:eq(2) span').text().trim(),
                dayTime: $row.find('td:eq(3) span').text().trim(),
                status: $row.find('td:eq(4) span span').text().trim() || 'Present' // Handle cases where status is directly in span
            };
            attendanceDetails.attendanceRecords.push(record);
        });

        return attendanceDetails;
    } catch (error) {
        console.error("Error parsing detailed attendance:", error.message);
        return null;
    }
}

// Modify fetchDetailedAttendance function
async function fetchDetailedAttendance(attendanceData, studentId, csrf, semesterSubId, client) {
    try {
        if (!attendanceData?.courses || !studentId || !csrf || !semesterSubId) {
            console.log("Missing required data for fetching detailed attendance");
            return;
        }

        const detailedAttendance = {
            semester: semesterSubId,
            courses: []
        };

        // Create array of promises for concurrent requests
        const requests = attendanceData.courses.map(course => {
            if (!course.courseId || !course.courseType) return null;

            const timestamp = calculateGMTTimestamp();
            return client.post('https://vtop.vit.ac.in/vtop/processViewAttendanceDetail', null, {
                params: {
                    _csrf: csrf,
                    semesterSubId: semesterSubId,
                    registerNumber: studentId,
                    courseId: course.courseId,
                    courseType: course.courseType,
                    authorizedID: studentId,
                    x: timestamp
                },
                headers: {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            }).then(response => ({
                courseCode: course.courseDetail.split(' - ')[0],
                data: response.data
            })).catch(error => {
                console.error(`Error fetching ${course.courseDetail}: ${error.message}`);
                return null;
            });
        }).filter(Boolean);

        // Execute all requests concurrently
        console.log(`Fetching detailed attendance for ${requests.length} courses...`);
        const results = await Promise.all(requests);

        // Parse and combine all responses
        results.forEach(result => {
            if (result && result.data) {
                const $ = cheerio.load(result.data);
                const parsedData = parseDetailedAttendance($, result.data);
                if (parsedData) {
                    detailedAttendance.courses.push({
                        courseCode: result.courseCode,
                        ...parsedData
                    });
                }
            }
        });

        // Just return the data instead of writing to file
        return detailedAttendance;
    } catch (error) {
        console.error("Error in fetchDetailedAttendance:", error.message);
        return null;
    }
}

// Modify the fetchAttendance function to include detailed attendance
async function fetchAttendance(studentId, csrf, semesterSubId, client) {
    try {
        const timestamp = calculateGMTTimestamp();
        const attendanceUrl = `https://vtop.vit.ac.in/vtop/processViewStudentAttendance`;
        
        const response = await client.post(attendanceUrl, null, {
            params: {
                _csrf: csrf,
                semesterSubId: semesterSubId,
                authorizedID: studentId,
                x: encodeURIComponent(timestamp)
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Parse and save attendance data as JSON
        const attendanceData = extractAttendance(response.data);
        return attendanceData;
    } catch (error) {
        console.error("Error fetching attendance:", error.message);
        return null;
    }
}

// Function to extract marks details
function extractMarks(html) {
    try {
        const $ = cheerio.load(html);
        const courses = [];

        // Find all course rows
        $('tr.tableContent').each((index, element) => {
            if ($(element).find('td').length === 9) { // Main course row
                const courseData = {
                    slNo: $(element).find('td').eq(0).text().trim(),
                    classNumber: $(element).find('td').eq(1).text().trim(),
                    courseCode: $(element).find('td').eq(2).text().trim(),
                    courseTitle: $(element).find('td').eq(3).text().trim(),
                    courseType: $(element).find('td').eq(4).text().trim(),
                    courseSystem: $(element).find('td').eq(5).text().trim(),
                    faculty: $(element).find('td').eq(6).text().trim(),
                    slot: $(element).find('td').eq(7).text().trim(),
                    courseMode: $(element).find('td').eq(8).text().trim(),
                    marks: []
                };

                // Get marks from the next row's nested table
                const marksTable = $(element).next().find('table.customTable-level1');
                marksTable.find('tr.tableContent-level1').each((i, markRow) => {
                    const mark = {
                        slNo: $(markRow).find('td').eq(0).find('output').text().trim(),
                        markTitle: $(markRow).find('td').eq(1).find('output').text().trim(),
                        maxMark: parseFloat($(markRow).find('td').eq(2).find('output').text().trim()),
                        weightagePercentage: parseFloat($(markRow).find('td').eq(3).find('output').text().trim()),
                        status: $(markRow).find('td').eq(4).find('output').text().trim(),
                        scoredMark: parseFloat($(markRow).find('td').eq(5).find('output').text().trim()),
                        weightageMark: parseFloat($(markRow).find('td').eq(6).find('output').text().trim()),
                        remark: $(markRow).find('td').eq(7).find('output').text().trim()
                    };
                    courseData.marks.push(mark);
                });

                courses.push(courseData);
            }
        });

        return { courses };
    } catch (error) {
        console.error("Error extracting marks:", error.message);
        return null;
    }
}

// Modify the fetchMarks function
async function fetchMarks(studentId, csrf, semesterSubId, client) {
    try {
        const marksUrl = `https://vtop.vit.ac.in/vtop/examinations/doStudentMarkView`;
        
        const response = await client.post(marksUrl, null, {
            params: {
                authorizedID: studentId,
                _csrf: csrf,
                semesterSubId: semesterSubId
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        const marksData = extractMarks(response.data);
        return marksData;
    } catch (error) {
        console.error("Error fetching marks:", error.message);
        return null;
    }
}

// Function to extract exam schedule details
function extractExamSchedule(html) {
    try {
        const $ = cheerio.load(html);
        const examData = {
            examTypes: []
        };
        
        let currentExamType = null;
        let currentExams = [];

        // Find all rows in the table
        $('.customTable tr.tableContent').each((index, row) => {
            // Check if this is an exam type header (FAT, CAT1, CAT2)
            const examTypeHeader = $(row).find('td.panelHead-secondary');
            if (examTypeHeader.length) {
                // If we have a previous exam type, save it
                if (currentExamType) {
                    examData.examTypes.push({
                        type: currentExamType,
                        exams: currentExams
                    });
                }
                
                // Start new exam type
                currentExamType = examTypeHeader.text().trim();
                currentExams = [];
                return;
            }

            // Skip if not a content row or if it's the main header
            if ($(row).find('td').length !== 13 || $(row).hasClass('tableHeader')) {
                return;
            }

            // Extract exam details
            const cells = $(row).find('td');
            const exam = {
                slNo: cells.eq(0).text().trim(),
                courseCode: cells.eq(1).text().trim(),
                courseTitle: cells.eq(2).text().trim(),
                courseType: cells.eq(3).text().trim(),
                classId: cells.eq(4).text().trim(),
                slot: cells.eq(5).text().trim(),
                examDate: cells.eq(6).text().trim() || null,
                examSession: cells.eq(7).text().trim() || null,
                reportingTime: cells.eq(8).text().trim() || null,
                examTime: cells.eq(9).text().trim() || null,
                venue: cells.eq(10).find('span').text().trim().replace('-', '') || null,
                seatLocation: cells.eq(11).find('span').text().trim().replace('-', '') || null,
                seatNo: cells.eq(12).find('span').text().trim().replace('-', '') || null
            };

            currentExams.push(exam);
        });

        // Add the last exam type
        if (currentExamType && currentExams.length) {
            examData.examTypes.push({
                type: currentExamType,
                exams: currentExams
            });
        }

        return examData;
    } catch (error) {
        console.error("Error extracting exam schedule:", error.message);
        return null;
    }
}

// Modify the fetchExamSchedule function
async function fetchExamSchedule(studentId, csrf, semesterSubId, client) {
    try {
        const examScheduleUrl = `https://vtop.vit.ac.in/vtop/examinations/doSearchExamScheduleForStudent`;
        
        const response = await client.post(examScheduleUrl, null, {
            params: {
                authorizedID: studentId,
                _csrf: csrf,
                semesterSubId: semesterSubId
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        const examScheduleData = extractExamSchedule(response.data);
        return examScheduleData;
    } catch (error) {
        console.error("Error fetching exam schedule:", error.message);
        return null;
    }
}

// Function to extract student profile data
function extractStudentProfile(html) {
    try {
        const $ = cheerio.load(html);
        const profileData = {
            personalInformation: {},
            educationalInformation: {},
            familyInformation: {},
            proctorInformation: {},
            hostelInformation: {},
            photos: {
                studentPhoto: null,
                proctorPhoto: null
            }
        };

        // Extract Personal Information
        $('#collapseOne table tr').each((i, row) => {
            const label = $(row).find('td:first').text().trim();
            const value = $(row).find('td:last').text().trim();
            if (label && value) {
                profileData.personalInformation[label.toLowerCase().replace(/\s+/g, '_')] = value;
            }
        });

        // Extract Educational Information
        $('#collapseTwo table tr').each((i, row) => {
            const label = $(row).find('td:first').text().trim();
            const value = $(row).find('td:last').text().trim();
            if (label && value) {
                profileData.educationalInformation[label.toLowerCase().replace(/\s+/g, '_')] = value;
            }
        });

        // Extract Family Information
        $('#collapseThree table tr').each((i, row) => {
            const label = $(row).find('td:first').text().trim();
            const value = $(row).find('td:last').text().trim();
            if (label && value) {
                profileData.familyInformation[label.toLowerCase().replace(/\s+/g, '_')] = value;
            }
        });

        // Extract Proctor Information
        $('#collapseFour table tr').each((i, row) => {
            const label = $(row).find('td:first').text().trim();
            const value = $(row).find('td:last').text().trim();
            if (label && value) {
                profileData.proctorInformation[label.toLowerCase().replace(/\s+/g, '_')] = value;
            }
        });

        // Extract Hostel Information
        $('#collapseFive table tr').each((i, row) => {
            const label = $(row).find('td:first').text().trim();
            const value = $(row).find('td:last').text().trim();
            if (label && value) {
                profileData.hostelInformation[label.toLowerCase().replace(/\s+/g, '_')] = value;
            }
        });

        // Try to extract photos
        const studentPhoto = $('.col-4.mt-4.mb-3 img').attr('src');
        const proctorPhoto = $('td[style*="background-color: #FAF0DD;"][rowspan="4"] img').attr('src');

        if (studentPhoto) {
            profileData.photos.studentPhoto = studentPhoto;
        }
        if (proctorPhoto) {
            profileData.photos.proctorPhoto = proctorPhoto;
        }

        return profileData;
    } catch (error) {
        console.error("Error extracting student profile:", error.message);
        return null;
    }
}

// Modify the fetchStudentProfile function
async function fetchStudentProfile(studentId, csrf, client) {
    try {
        const profileUrl = `https://vtop.vit.ac.in/vtop/studentsRecord/StudentProfileAllView`;
        
        const response = await client.post(profileUrl, null, {
            params: {
                verifyMenu: true,
                authorizedID: studentId,
                _csrf: csrf,
                nocache: new Date().getTime()
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Parse the HTML response and convert to JSON
        const profileData = extractStudentProfile(response.data);
        
        return profileData;
    } catch (error) {
        console.error("Error fetching student profile:", error.message);
        return null;
    }
}

// Function to extract fee receipt details
function extractFeeReceipts(html) {
    try {
        const $ = cheerio.load(html);
        const feeData = {
            applicationNumber: null,
            registrationNumber: null,
            receipts: []
        };

        // Extract application number and registration number
        const applnoInput = $('input[name="applno"]').first();
        const regnoInput = $('input[name="regno"]').first();
        
        if (applnoInput && regnoInput) {
            feeData.applicationNumber = applnoInput.val();
            feeData.registrationNumber = regnoInput.val();
        }

        // Find the receipts table
        $('.table-bordered tr').each((index, row) => {
            // Skip header row
            if (index === 0) return;

            const cells = $(row).find('td');
            if (cells.length >= 5) {
                const receipt = {
                    invoiceNumber: cells.eq(0).text().trim(),
                    receiptNumber: cells.eq(1).text().trim(),
                    date: cells.eq(2).text().trim(),
                    amount: parseFloat(cells.eq(3).text().trim()) || 0,
                    campusCode: cells.eq(4).text().trim()
                };
                feeData.receipts.push(receipt);
            }
        });

        return feeData;
    } catch (error) {
        console.error("Error extracting fee receipts:", error.message);
        return null;
    }
}

// Modify the fetchFeeReceipts function
async function fetchFeeReceipts(studentId, csrf, client) {
    try {
        const feeReceiptsUrl = `https://vtop.vit.ac.in/vtop/finance/getStudentReceipts`;
        
        const response = await client.post(feeReceiptsUrl, null, {
            params: {
                verifyMenu: true,
                authorizedID: studentId,
                _csrf: csrf,
                nocache: new Date().getTime()
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        // Parse and save fee receipt data as JSON
        const feeReceiptData = extractFeeReceipts(response.data);
        return feeReceiptData;
    } catch (error) {
        console.error("Error fetching fee receipts:", error.message);
        return null;
    }
}

// Function to extract digital assignments
function extractDigitalAssignments(html) {
    try {
        const $ = cheerio.load(html);
        const assignmentData = {
            semesterId: $('#semesterSubId').val(),
            courses: []
        };

        // Find all rows in the assignments table
        $('.customTable tr.tableContent').each((index, row) => {
            const cells = $(row).find('td');
            
            // Skip if not enough cells
            if (cells.length < 7) return;

            const course = {
                slNo: cells.eq(0).text().trim(),
                classNumber: cells.eq(1).text().trim(),
                courseCode: cells.eq(2).text().trim(),
                courseTitle: cells.eq(3).text().trim(),
                courseType: cells.eq(4).text().trim(),
                facultyName: cells.eq(5).text().trim(),
                dashboardLink: {
                    classId: $(cells.eq(6)).find('button').attr('onclick')?.match(/'([^']+)'/)?.[1] || null
                }
            };

            assignmentData.courses.push(course);
        });

        return assignmentData;
    } catch (error) {
        console.error("Error extracting digital assignments:", error.message);
        return null;
    }
}

// Modify the extractAssignmentDetails function
function extractAssignmentDetails(html, courseCode) {
    try {
        const $ = cheerio.load(html);
        const assignments = [];
        
        // Get course details from the first table
        const courseInfo = {
            courseCode,
            courseTitle: $('.customTable tr.tableContent td:nth-child(3)').first().text().trim(),
            courseType: $('.customTable tr.tableContent td:nth-child(4)').first().text().trim(),
            classNumber: $('.customTable tr.tableContent td:nth-child(5)').first().text().trim(),
        };

        // Find all assignment rows in the table
        $('.customTable tr.tableContent-level1, .customTable tr.tableContent').each((index, row) => {
            const cells = $(row).find('td');
            
            // Only process rows that have assignment data (Sl.No, Title, etc.)
            if (cells.length >= 5) {
                const slNo = cells.eq(0).text().trim();
                // Skip if not a valid assignment row (headers or empty rows)
                if (!slNo || !slNo.match(/^\d+$/)) return;

                const assignment = {
                    slNo: slNo,
                    title: cells.eq(1).text().trim(),
                    maxMark: parseFloat(cells.eq(2).text().trim()) || 0,
                    weightagePercentage: parseFloat(cells.eq(3).text().trim()) || 0,
                    dueDate: cells.eq(4).find('span').text().trim(),
                    lastUpdatedOn: $(cells[6]).text().trim() // Column 7 has the last updated date
                };

                // Only add assignments that have actual data
                if (assignment.title && assignment.maxMark > 0) {
                    assignments.push(assignment);
                }
            }
        });

        // Only return if we have valid data
        if (assignments.length > 0) {
            return {
                ...courseInfo,
                assignments
            };
        }
        return null;

    } catch (error) {
        console.error(`Error extracting assignment details for ${courseCode}:`, error.message);
        return null;
    }
}

// Modify the fetchAssignmentDetails function
async function fetchAssignmentDetails(studentId, csrf, course, client) {
    try {
        const timestamp = new Date().toUTCString();
        const assignmentUrl = `https://vtop.vit.ac.in/vtop/examinations/processDigitalAssignment`;
        
        const response = await client.post(assignmentUrl, null, {
            params: {
                authorizedID: studentId,
                x: timestamp,
                classId: course.dashboardLink.classId,
                _csrf: csrf
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        return extractAssignmentDetails(response.data, course.courseCode);

    } catch (error) {
        return null;
    }
}

// Modify the fetchDigitalAssignments function
async function fetchDigitalAssignments(studentId, csrf, semesterSubId, client) {
    try {
        const assignmentUrl = `https://vtop.vit.ac.in/vtop/examinations/doDigitalAssignment`;
        
        const response = await client.post(assignmentUrl, null, {
            params: {
                authorizedID: studentId,
                _csrf: csrf,
                semesterSubId: semesterSubId
            },
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        });

        const assignmentData = extractDigitalAssignments(response.data);
        if (!assignmentData?.courses?.length) return null;

        const startTime = Date.now();
        const detailedAssignmentsPromises = assignmentData.courses.map(course => 
            fetchAssignmentDetails(studentId, csrf, course, client)
                .catch(() => null)
        );

        const detailedAssignments = await Promise.all(detailedAssignmentsPromises);
        const validAssignments = detailedAssignments.filter(Boolean);
        
        return {
            overview: assignmentData,
            details: validAssignments
        };

    } catch (error) {
        console.error("Error in fetchDigitalAssignments:", error.message);
        return null;
    }
}

// API Endpoints
app.post('/initialdata', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ success: false, message: "Username and password are required" });
    }

    try {
        // Get or create client for this user
        const client = getUserClient(username);
        let studentId, csrf;
        let session = userSessions.get(username);

        // Check if we have valid session data
        if (session?.studentId && session?.csrf) {
            studentId = session.studentId;
            csrf = session.csrf;
            console.log(`Using existing session for user: ${username}`);
        } else {
            console.log(`No existing session, creating new login for user: ${username}`);
            // Need to login first
            const loginResult = await attemptLogin(username, password, client);
            
            if (!loginResult.success) {
                userSessions.delete(username);
                return res.status(401).json(loginResult);
            }

            // Extract required tokens
            studentId = extractStudentId(loginResult.data);
            const csrfMatch = loginResult.data.match(/name="_csrf"\s+value="([^"]+)"/);
            csrf = csrfMatch ? csrfMatch[1] : null;

            if (!studentId || !csrf) {
                userSessions.delete(username);
                return res.status(500).json({ 
                    success: false, 
                    message: "Failed to extract required tokens" 
                });
            }

            // Create and store new session
            session = {
                client,
                studentId,
                csrf,
                lastUsed: Date.now()
            };
            userSessions.set(username, session);
            console.log(`Created new session for user: ${username}`);
        }

        // Fetch all initial data concurrently
        const [profileData, gradeData, semesterList, feeData] = await Promise.all([
            fetchStudentProfile(studentId, csrf, client),
            fetchGradeHistory(studentId, csrf, client),
            fetchSemesterList(studentId, csrf, client),
            fetchFeeReceipts(studentId, csrf, client)
        ]);

        // Update session last used time
        session.lastUsed = Date.now();

        // Return comprehensive response
        res.json({
            success: true,
            studentId,
            csrf,
            profile: profileData,
            gradeHistory: gradeData,
            semesterList: semesterList,
            feeReceipts: feeData,
            sessionInfo: {
                isNewSession: !session.existingSession,
                created: new Date(session.lastUsed).toISOString(),
                expiresIn: SESSION_TIMEOUT / 1000 // in seconds
            },
            fetchTimestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error("Error in /initialdata endpoint:", error);
        userSessions.delete(username); // Clear session on error
        res.status(500).json({ 
            success: false, 
            message: "Internal server error",
            error: error.message 
        });
    }
});

app.post('/semesterdata', async (req, res) => {
    const { username, password, semesterId } = req.body;
    
    if (!username || !password || !semesterId) {
        return res.status(400).json({ 
            success: false, 
            message: "Username, password, and semesterId are required" 
        });
    }

    try {
        // Get or create client for this user
        const client = getUserClient(username);
        let studentId, csrf;
        let session = userSessions.get(username);

        // Check if we have valid session data
        if (session?.studentId && session?.csrf) {
            studentId = session.studentId;
            csrf = session.csrf;
            console.log(`Using existing session for user: ${username}`);
        } else {
            console.log(`No existing session, creating new login for user: ${username}`);
            // Need to login first
            const loginResult = await attemptLogin(username, password, client);
            
            if (!loginResult.success) {
                userSessions.delete(username);
                return res.status(401).json(loginResult);
            }

            // Extract required tokens
            studentId = extractStudentId(loginResult.data);
            const csrfMatch = loginResult.data.match(/name="_csrf"\s+value="([^"]+)"/);
            csrf = csrfMatch ? csrfMatch[1] : null;

            if (!studentId || !csrf) {
                userSessions.delete(username);
                return res.status(500).json({ 
                    success: false, 
                    message: "Failed to extract required tokens" 
                });
            }

            // Create and store new session
            session = {
                client,
                studentId,
                csrf,
                lastUsed: Date.now()
            };
            userSessions.set(username, session);
            console.log(`Created new session for user: ${username}`);
        }

        // Fetch all semester data concurrently
        const [
            timeTableData,
            attendanceData,
            marksData,
            examScheduleData,
            gradeViewData,
            assignmentsData
        ] = await Promise.all([
            fetchTimeTable(studentId, csrf, semesterId, client),
            fetchAttendance(studentId, csrf, semesterId, client),
            fetchMarks(studentId, csrf, semesterId, client),
            fetchExamSchedule(studentId, csrf, semesterId, client),
            fetchGradeView(studentId, csrf, semesterId, client),
            fetchDigitalAssignments(studentId, csrf, semesterId, client)
        ]);

        // Update session last used time
        session.lastUsed = Date.now();

        // Return comprehensive response
        res.json({
            success: true,
            semesterId,
            data: {
                timeTable: timeTableData,
                attendance: {
                    summary: attendanceData,
                    detailed: await fetchDetailedAttendance(
                        attendanceData,
                        studentId,
                        csrf,
                        semesterId,
                        client
                    )
                },
                marks: marksData,
                examSchedule: examScheduleData,
                gradeView: gradeViewData,
                assignments: assignmentsData
            },
            sessionInfo: {
                isNewSession: !session.existingSession,
                lastUsed: new Date(session.lastUsed).toISOString(),
                expiresIn: Math.floor((SESSION_TIMEOUT - (Date.now() - session.lastUsed)) / 1000)
            },
            fetchTimestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error("Error in /semesterdata endpoint:", error);
        userSessions.delete(username); // Clear session on error
        res.status(500).json({ 
            success: false, 
            message: "Internal server error",
            error: error.message 
        });
    }
});

// Start the server
app.listen(port, '0.0.0.0', () => { 
    console.log(`Server running at http://0.0.0.0:${port}`); 
});
