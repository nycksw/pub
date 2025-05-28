---
tags:
  - hack
---

# Passing the OSCP Exam

I failed the OSCP exam. I passed the OSCP exam. This is my tale.

# My Background

I've worked in SRE for many years at a big company, but management left me rusty. I have a strong Linux, networking, and system design background, and I can code a little. I was clueless about Windows initially.

# Training Plan and Timeline

* **2023 April**: I started playing around on HTB and got more and more interested in security.
* **2023 October**: Decided OSCP was a good goal. Initially planned for two months of study, starting with HTB Academy's Penetration Tester curriculum.
* **2023 December**: I realized my two-month plan was pure fantasy.
* **2024 January–March**: Completed PEN-200 course, 100% of the labs, and continued with HTB Academy and TJNull's list until I felt ready.

# First Attempt: Zero Points?

My exam was scheduled at the end of April, 2024. Despite an encouraging start full of attack surfaces and leaked credentials, I got nowhere. I worked for 18 of the 24 hours, but I couldn’t secure a foothold. It all felt much harder than the PEN-200 labs. A crushing defeat.

# Stages of Grief, New Plan

I received the rejection email on May 3, 2024. Three weeks of self-pity and frustration led me to double down on fundamentals, slower enumeration, and more thorough notetaking. I shifted from hating all things Windows to appreciating the security challenges inherent in Windows and Active Directory.

* **2024 June–July**: Focused on Windows/AD with HTB Academy and HTB CTFs.
* **2024 August–September**: Completed about 70 HTB/PG targets with meticulous notes, integrating TJNull’s and Lainkusanagi’s OSCP lists for practice.

# Second Attempt: 90 Points

October 15, 2024, was retake day.

* **07:00**: Started. Within minutes I exploited a web service for an "admin" login on the AD set. Then I spun for a while in a SQLi rabbit hole.
* **08:55**: Got RCE. Got PE six minutes later.
* **11:28**: Domain Admin on AD set.
* **11:38–13:52**: Owned two of the three standalone machines.

That was already 90 points in about seven hours (hooray!) but I couldn’t own the final target, despite identifying several potential paths.

The final target was very similar to the most frustrating target from my first exam. I found all the same potential attack points as my first time around, but I uncovered another couple of interesting things (including credentials!) and so I figured it was only a matter of time and persistence.

For the next six hours, from about 2 PM until 8 PM, I tried breaking that final target, but I was stuck. After 8 PM I worked on a draft of the report, resetting targets and working through all of the exploits to make sure I had screenshots and that my descriptions of the exploits were correct. I finished a solid rough draft around 11:45 PM and went to sleep.

I woke up, showered, drank coffee, and took one last run at the final standalone with about 90 minutes remaining. Unfortunately, I just couldn't get it, not even so much as a foothold.

I ate breakfast and began my final draft of the report, which took me about three hours to finish. 50 pages! In the process of writing it, I realized an obvious attack vector I had missed, a simple thing sitting right there in a big field of rabbit holes. I had dismissed it early on because it felt like a waste of time, and yet I proceeded to burn eight solid hours on everything else but that.

# Key Lessons

* **Don't Fool Yourself**: I was over-relying on hints during PEN-200 labs, rationalizing that I "would have figured it out" to such an extent that I wasn't even consciously realizing it. Explicitly categorizing practice targets into *No Hints Needed*, *Learned Something*, or *Try Harder* helped me correct this cognitive error.
* **Prioritize Weaknesses**: Focusing on Windows improved my performance significantly. The shift was evident when I started accidentally typing PowerShell commands on Linux boxes!
* **Recognize Rabbit Holes**: This comes through repetition, but you'll need to realize when you've tried everything you know and consider whether the current approach is distracting you from a better one.

# My OSCP Study Tracker

I modified the legendary TJNull and Lainkusanagi lists into an [OSCP Study Tracker](https://docs.google.com/spreadsheets/d/1nzEN0G6GzneWCfs6qte6Qqv-i8cV_j6po-tFlZAOx1k/edit?usp=sharing) for easy sorting and filtering. It tracks *No Hints Needed*, *Learned Something*, and *Try Harder* results. I also added a `Released` date-field for each machine, because it was useful to know if I was attacking a machine that was six years old or a more recent one. That also allows you to use Google dorks like `before:2024-08-31` to avoid spoilers. I took liberties by removing some items from those lists, e.g. I only included HTB and PG Practice platforms.

# TL;DR

Don't fool yourself about your reliance on hints. Make your weakest areas your strengths. Learn what rabbit holes feel like. **Writing up your report with time left on the clock may reveal hidden answers**.
