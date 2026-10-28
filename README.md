\# Task 6: Decode and Interpret Security Logs



\## 1. Objective

The objective of this project is to analyse sample security logs, identify unusual activities, and prepare a report explaining the findings.



\## 2. Project Files

\- `log\_analyzer.py` – Analyses the security logs and detects suspicious patterns.

\- `sample\_logs.csv` – Contains sample security log data.

\- `findings\_report.txt` – Contains the analysis results and explanations of the findings.



\## 3. Requirements

\- Python 3 installed on the computer.

\- All three project files saved in the same folder.



\## 4. How to Run

1\. Open PowerShell.

2\. Navigate to the project folder:

&#x20;  `cd D:\\Task\_6\_Decode\_and\_Interpret\_Security\_Logs`

3\. Run the program:

&#x20;  `python log\_analyzer.py`

4\. Review the terminal output and open `findings\_report.txt` to read the detailed report.



\## 5. Test Results

The program was executed successfully using the provided sample log data.



\- Logs analysed: 21

\- Findings generated: 4

\- High severity: 1

\- Medium severity: 3



The findings include multiple failed logins, repeated requests, and unusual login times.



\## 6. Conclusion

The project demonstrates how basic log analysis can help identify suspicious security patterns. These findings are indicators that may require further investigation; they do not independently prove that an attack occurred.



\## 7. Limitations

The project uses sample log data and predefined detection rules. Real-world environments may require additional validation and more advanced detection methods.



