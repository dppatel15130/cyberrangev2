# Guacamole Manual Setup Guide

## Current Status
✅ Guacamole is accessible at: http://172.16.200.136:8080/guacamole  
❌ API authentication is having issues (500 error)  
✅ User creation service is integrated into the backend  

## Manual User Creation Process

Since the API is having issues, you can manually create users in Guacamole:

### 1. Access Guacamole Admin Panel
- URL: http://172.16.200.136:8080/guacamole
- Login: guacadmin/guacadmin

### 2. Create Users for Each Team Member
For each user who joins the competition:

1. Go to **Settings** → **Users**
2. Click **New User**
3. Fill in the details:
   - **Username**: Same as CyberRange username (e.g., "admin")
   - **Password**: sac@1234
   - **Full Name**: Same as username
   - **Email**: username@cyberrange.com
   - **Organization**: CyberRange
   - **Role**: USER

### 3. Assign Connection to User
1. Select the user you just created
2. Go to **Settings** → **Users** → **[Username]** → **Permissions**
3. Under **Connections**, add the "Windows7-Target" connection
4. Save the permissions

### 4. User Access Information
Once created, users can:
- Login to: http://172.16.200.136:8080/guacamole
- Username: Their CyberRange username
- Password: sac@1234
- Access: Windows7-Target connection
- Target VM: admin/password123

## Automated Integration Status

The backend is configured to automatically create Guacamole users when:
1. A user joins a team
2. A team joins a match
3. Admin manually triggers user creation

However, due to the API authentication issue, the automated process may fail. In that case, use the manual process above.

## Testing Commands

```bash
# Test Guacamole connectivity
curl http://172.16.200.136:8080/guacamole

# Test from Kali Linux to target
ping 172.16.26.139
nmap -sS -p 445,3389,80 172.16.26.139
```

## Next Steps

1. **Manual Setup**: Create users manually in Guacamole admin panel
2. **API Fix**: Investigate why Guacamole API authentication is failing
3. **Test Access**: Have users test their Guacamole access
4. **Start Match**: Begin the cyber warfare competition

## Troubleshooting

If users can't access Guacamole:
1. Check if user exists in Guacamole admin panel
2. Verify connection permissions are assigned
3. Ensure target VM (172.16.26.139) is running
4. Check network connectivity between Kali (172.16.200.136) and target (172.16.26.139)
