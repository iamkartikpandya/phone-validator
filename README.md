# Phone Number Verifyer

A web application that allows users to upload CSV files containing phone numbers, process them using the NumLookup API, and download enriched contact data.

## Features

* User registration and login
* Secure API key storage for NumLookup API
* CSV upload support
* Column selection for phone number field
* Phone number enrichment using NumLookup API
* Download processed CSV output

## User Flow

1. User registers or logs in
2. User enters their NumLookup API key
3. User uploads a CSV file
4. User selects the column containing phone numbers
5. System processes each phone number through NumLookup API
6. User downloads enriched CSV file

## Output Fields

The processed CSV returns the following columns:

* name
* phone
* email
* website
* category
* address
* city
* region
* zip
* valid
* formatted_number
* local_format
* international_format
* country_prefix
* country_code
* country_name
* location
* carrier
* line_type

## Installation

```bash
git clone <your-repo-url>
cd <project-folder>
npm install
npm run dev
```

## Environment Variables

Create a `.env` file:

```env
DATABASE_URL=
JWT_SECRET=
NEXTAUTH_SECRET=
```

If NumLookup key is stored server-side:

```env
NUMLOOKUP_API_URL=https://api.numlookupapi.com
```

## Required Modules

Make sure these are installed:

```bash
npm install axios csv-parser papaparse multer
```

If authentication is used:

```bash
npm install bcrypt jsonwebtoken
```

## Core Functional Requirements

### Authentication

* Register user
* Login user
* Session handling

### CSV Upload

* File validation
* CSV parser
* Max file size control

### Column Mapping

* Detect CSV headers
* Let user select phone number column

### API Processing

* Send each phone number to NumLookup API
* Handle API limits
* Retry failed requests

### CSV Export

* Merge original + API response
* Generate downloadable CSV

## Recommended Folder Structure

```bash
/src
  /components
  /pages
  /api
  /utils
  /services
```

## Important Checks Before Running

* API route for NumLookup processing exists
* CSV parser correctly reads headers
* API key is passed securely
* Error handling for invalid phone numbers
* Loading state during processing
* Output CSV generation works

## Security Notes

* Never expose API keys publicly
* Store user keys encrypted if saving in database
* Validate uploaded CSV files

## 🔍 What may still be missing to make it run

Since I haven’t seen your project files yet, I **can’t truly review what’s missing yet**.

Please upload or paste:

* `package.json`
* main app files / folder structure
* API route files
* CSV processing file
* auth file

Then I’ll check:
✅ what is missing
✅ what will break on run
✅ GitHub push readiness
✅ deployment readiness

If you want, send the files and I’ll review them like a production launch checklist ⚡
