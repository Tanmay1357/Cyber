===============================================================================
 AI-POWERED NETWORK INTRUSION DETECTION SYSTEM WITH EXPLAINABLE AI (NIDS-XAI)
 DVD / CD  -  READ ME
===============================================================================

 Author      : Shayaam Shaheem  (S082246)
 Supervisor  : Ibrahim Thoriq
 Programme   : Bachelor of Computer Science
 Institution : Faculty of Engineering, Science and Technology,
               The Maldives National University

 This READ ME explains what is on the disc and how to get started. For full
 installation and usage instructions, open USER_MANUAL.txt.

-------------------------------------------------------------------------------
 1. WHAT IS ON THIS DISC
-------------------------------------------------------------------------------

 This package contains the software and complete source code, provided either
 as Software.zip (on the CD - extract it here) or as the nids_xai\ and web\
 folders directly (in the full download). Either way you get two folders:

   nids_xai\   Python backend, detection engine, CLI, trained models, examples
   web\        The web dashboard (React frontend)

 START.bat            One-click launcher (run after the software is in place)
 USER_MANUAL.txt      Step-by-step guide to install, run and use the system
 README.txt           This file
 Final.docx / Final.pdf   The thesis / report        (included on the CD)

 TRAINING DATASETS (CIC-IDS2017 / CIC-IDS2018):
   These are large. They may ALREADY be included in  nids_xai\data\raw\  (in
   the full download). If that folder is empty, download them separately:
        Google Drive:  https://drive.google.com/drive/folders/1rlEoxEmP2AwBUsduFIhs9xTdekHvEeab?usp=sharing
   or from the official sources listed in the User Manual. The datasets are
   only needed to RE-TRAIN the model; detection, evaluation and explanations
   work without them (a trained model is already included).

 Note: the developed software and the source code are the same files. The
 project runs directly from its source (Python and React).

-------------------------------------------------------------------------------
 2. SYSTEM REQUIREMENTS
-------------------------------------------------------------------------------

 - Windows 10 or 11
 - Python 3.10 or higher      (https://www.python.org/downloads/)
 - Node.js 18 or higher       (https://nodejs.org/)   [for the web dashboard]
 - 8 GB RAM minimum (16 GB recommended for training)
 - About 5 GB free disk space (for datasets and trained models)

 Note: the datasets and the trained model files are large and are not required
 just to view the code or the thesis. They are needed only if you want to
 re-train or re-run detection from scratch. See the User Manual.

-------------------------------------------------------------------------------
 3. QUICK START (WINDOWS)
-------------------------------------------------------------------------------

 STEP 1  Copy this whole folder from the disc to your hard drive
         (running directly from the DVD is slow and read-only).
         If the software is supplied as a zip file (for example
         Software.zip), extract it here first so that the nids_xai and
         web folders sit next to START.bat.

 STEP 2  Open the nids_xai folder and double-click:
             setup.bat
         This creates the Python environment and installs everything.
         Wait for "Setup Complete".

 STEP 3  Install the dashboard. Open a Command Prompt in the web folder
         and run:
             npm install

 STEP 4  Start the system by double-clicking:
             START.bat
         (or follow the manual to start the backend and frontend by hand)
         Then open your web browser at:
             http://localhost:5173

 For everything else - using each screen, running the live demo, training,
 and troubleshooting - see USER_MANUAL.txt.

-------------------------------------------------------------------------------
 4. IMPORTANT NOTES
-------------------------------------------------------------------------------

 - This system is built for detection and explanation in a controlled lab
   environment. It does not block or prevent traffic.

 - The CIC-IDS2017 and CIC-IDS2018 datasets are the property of the Canadian
   Institute for Cybersecurity and are used here for academic purposes only.

 - If you only want to read the report, open Final.pdf. Nothing needs to be
   installed for that.

===============================================================================
 End of README
===============================================================================
