# 3D Upload Site (STL/3MF)

Simple website with a public form to submit contact details and upload a 3D model (STL/3MF), plus a password-protected admin page. Uses a JSON file as a permanent "mock database" stored locally.

## Features

- Public home page with required fields:
  - Namn, Mejl, Kort beskrivning, Har du preferens på vem, Hur bråttom
  - File upload: .stl or .3mf (100MB limit)
- Permanent mock DB: `data/submissions.json`
- Files saved to `uploads/`
- Password-protected admin page at `/admin` (Basic Auth)
- Admin can download uploaded files

## Setup

1. Install dependencies

   ```powershell
   cd "d:\withe\Vs code\3D"
   npm install express multer express-basic-auth dotenv uuid
   ```

2. (Optional) Create a `.env` to customize port and admin credentials. Copy `.env.example`:

   ```powershell
   Copy-Item .env.example .env
   # Then edit .env to change ADMIN_PASSWORD
   ```

3. Run the server

   ```powershell
   npm start
   ```

4. Open http://localhost:3000 in your browser.

- Visit `/admin` for the admin page.
  - Default credentials: `admin` / `admin123`
  - Change via environment variables `ADMIN_USER` and `ADMIN_PASSWORD`.

## Notes

- The database is the JSON file at `data/submissions.json`. It's kept permanently on disk.
- Uploaded files are saved under `uploads/` with unique names.
- To change file size limit or allowed types, see `server.js` (multer configuration).

## Safety

- Admin downloads are behind Basic Auth. Avoid serving `uploads/` as a public static folder.
- Do not upload confidential data; this is a simple demo server.
