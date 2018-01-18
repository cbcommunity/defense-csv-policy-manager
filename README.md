# Manage Cb Defense security policies through an Excel worksheet

This repository contains a Python script and Excel workbook to manage
security policies in bulk. It can be easier to keep track of rules via a comment-field. 
And with the integrated backup of the policies we achieve a first level of versioning for the policies.

The Python script requires Python 2.7.

![Excel worksheet](/images/excel_worksheet.png)

Guide to the columns in the Excel sheet:

* Column A: Dropdown to select the Action
* Column B: Dropdown to select the Type of Application
* Column C: The Application 
* Column D: Dropdown to select the operation
* Column E: A comment field 
* Column F: The names of the policies , if you want to have the rule in the policy you have to  put a "1" into the cell

You can add as many policies as you wish ..

When you have defined your rules click on the button to create a csv-file called „policyrules.csv“

Now call „python csvsplitter.py“ to break the CSV-File into an individual CSV-file per policy. The created csv-files will be named like the policy.

Next task is to call the policymanager.py to update the policies. In my example we will update the VIP-Policy.
You can use either credential profiles or explicit API token and hostname as command line parameters
to the `policy_manager.py` script. The following example will use the "default" profile; add `--profile profile_name`
to the command line if using a different credential profile.

```
python policy_manager.py csvupdate -N VIP -f VIP.csv  
```

The following will happen:

A Backup of the policy is written into `Backup/VIP/vip-timestamp.json`
Existing Policies will be modified, missing Rules will be added
Rules not included in the CSV will be deleted
 

Additional commands:

To list all policies:

```
python policy_manager.py list  
```
 

To export a policy:

```
python policy_manager.py  export -N "policyname"
```
 

To import an exported policy:

```
python policy_manager.py import -N "policyname" -d "Description" -f policyfile
```
 

I haven't added much of error checking so far so please test before using it in a production environment 

 
Known issues / limits so far:

* Policy must pre-exist as only the rules are updates not the other stuff
* Still working on updating/restoring an entire existing policy via previously exported policy

