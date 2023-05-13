require 'httpclient'

module RedmineSlack
class Listener < Redmine::Hook::Listener
	def redmine_slack_issues_new_after_save(context={})
		issue = context[:issue]

		channel = channel_for_user_or_group issue.assigned_to
		mention = mention_for_user_or_group issue.assigned_to

		return unless channel
		return if issue.is_private?

		msg = "#{mention} \n[#{escape issue.project}] #{escape issue.author} created \n<#{object_url issue}|#{escape issue}>#{mentions issue.description}"

		attachment = {}
		attachment[:text] = escape issue.description if issue.description
		attachment[:fields] = [{
			:title => I18n.t("field_status"),
			:value => escape(issue.status.to_s),
			:short => true
		}, {
			:title => I18n.t("field_priority"),
			:value => escape(issue.priority.to_s),
			:short => true
		}, {
			:title => I18n.t("field_assigned_to"),
			:value => escape(issue.assigned_to.to_s),
			:short => true
		}]

		attachment[:fields] << {
			:title => I18n.t("field_watcher"),
			:value => escape(issue.watcher_users.join(', ')),
			:short => true
		} if Setting.plugin_redmine_slack['display_watchers'] == 'yes'

		speak msg, channel, attachment
	end

	def redmine_slack_issues_edit_after_save(context={})
		issue = context[:issue]
		journal = context[:journal]

		return if issue.is_private? || journal.private_notes?

		# Check if the assignee has been changed
		assignee_change_detail = journal.details.find { |detail| detail.prop_key == 'assigned_to_id' }

		# Get assignees based on the assignee_change_detail
		assignees = get_assignees(assignee_change_detail, issue)

		# Perform the following actions for each assignee
		assignees.each do |assignee|
			channel = channel_for_user_or_group assignee
			mention = mention_for_user_or_group assignee

			# If the assignee has been changed, or if the following conditions are met, send the message:
			# - The channel exists
			# - The setting to post updates is turned on for the assignee
			next unless assignee_change_detail || (channel && is_post_updates?(assignee))

			msg = "#{mention} \n[#{escape issue.project}] #{escape journal.user.to_s} updated \n<#{object_url issue}|#{escape issue}>#{mentions journal.notes}"

			attachment = {}
			attachment[:text] = escape journal.notes if journal.notes
			attachment[:fields] = journal.details.map { |d| detail_to_field d }

			# Send the message
			speak msg, channel, attachment
		end
	end

	# Returns the old and/or new assignee(s) based on the assignee change detail. If there's no assignee change, returns the current assignee.
	def get_assignees(assignee_change_detail, issue)
		if assignee_change_detail
			old_assignee = assignee_change_detail.old_value && User.find_by(id: assignee_change_detail.old_value)
			new_assignee = User.find(assignee_change_detail.value)
			[old_assignee, new_assignee].compact
		else
			[issue.assigned_to].compact
		end
	end

	def model_changeset_scan_commit_for_issue_ids_pre_issue_update(context={})
		issue = context[:issue]
		journal = issue.current_journal
		changeset = context[:changeset]

		channel = channel_for_user_or_group issue.assigned_to
		mention = mention_for_user_or_group issue.assigned_to

		return unless channel and issue.save
		return if issue.is_private?

		msg = "#{mention} \n[#{escape issue.project}] #{escape journal.user.to_s} updated \n<#{object_url issue}|#{escape issue}>"

		repository = changeset.repository

		if Setting.host_name.to_s =~ /\A(https?\:\/\/)?(.+?)(\:(\d+))?(\/.+)?\z/i
			host, port, prefix = $2, $4, $5
			revision_url = Rails.application.routes.url_for(
				:controller => 'repositories',
				:action => 'revision',
				:id => repository.project,
				:repository_id => repository.identifier_param,
				:rev => changeset.revision,
				:host => host,
				:protocol => Setting.protocol,
				:port => port,
				:script_name => prefix
			)
		else
			revision_url = Rails.application.routes.url_for(
				:controller => 'repositories',
				:action => 'revision',
				:id => repository.project,
				:repository_id => repository.identifier_param,
				:rev => changeset.revision,
				:host => Setting.host_name,
				:protocol => Setting.protocol
			)
		end

		attachment = {}
		attachment[:text] = ll(Setting.default_language, :text_status_changed_by_changeset, "<#{revision_url}|#{escape changeset.comments}>")
		attachment[:fields] = journal.details.map { |d| detail_to_field d }

		speak msg, channel, attachment
	end

	def controller_wiki_edit_after_save(context = { })
		return unless Setting.plugin_redmine_slack['post_wiki_updates'] == '1'

		project = context[:project]
		page = context[:page]

		user = page.content.author
		project_url = "<#{object_url project}|#{escape project}>"
		page_url = "<#{object_url page}|#{page.title}>"
		comment = "[#{project_url}] #{page_url} updated by *#{user}*"
		if page.content.version > 1
			comment << " [<#{object_url page}/diff?version=#{page.content.version}|difference>]"
		end

		channel = channel_for_project project

		attachment = nil
		if not page.content.comments.empty?
			attachment = {}
			attachment[:text] = "#{escape page.content.comments}"
		end

		speak comment, channel, attachment
	end

	def speak(msg, channel, attachment=nil)
		url = 'https://slack.com/api/chat.postMessage'
		auth_token = Setting.plugin_redmine_slack['auth_token'] # Bot User OAuth Token
		username = Setting.plugin_redmine_slack['username']
		icon = Setting.plugin_redmine_slack['icon']

		# create header
		headers = {
			'Content-type' => 'application/json',
			'Authorization' => "Bearer #{auth_token}"
		}

		# create post body
		params = {
			:text => msg,
			:link_names => 1,
		}
		params[:username] = username if username
		params[:channel] = channel if channel
		params[:attachments] = [attachment] if attachment

		if icon and not icon.empty?
			if icon.start_with? ':'
				params[:icon_emoji] = icon
			else
				params[:icon_url] = icon
			end
		end

		begin
			client = HTTPClient.new
			client.ssl_config.add_trust_ca(OpenSSL::X509::DEFAULT_CERT_FILE)
			client.ssl_config.ssl_version = :auto
			client.post_async url, :body => params.to_json, :header => headers
		rescue Exception => e
			Rails.logger.warn("cannot connect to #{url}")
			Rails.logger.warn(e)
		end
	end

private
	def escape(msg)
		msg.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;")
	end

	def object_url(obj)
		if Setting.host_name.to_s =~ /\A(https?\:\/\/)?(.+?)(\:(\d+))?(\/.+)?\z/i
			host, port, prefix = $2, $4, $5
			Rails.application.routes.url_for(obj.event_url({
				:host => host,
				:protocol => Setting.protocol,
				:port => port,
				:script_name => prefix
			}))
		else
			Rails.application.routes.url_for(obj.event_url({
				:host => Setting.host_name,
				:protocol => Setting.protocol
			}))
		end
	end

	def channel_for_user_or_group(assigned_to)
		return nil if assigned_to.blank?

		if assigned_to.class.name == "User"
			cf = UserCustomField.find_by_name("Slack Channel")
		elsif assigned_to.class.name == "Group"
			cf = GroupCustomField.find_by_name("Slack Channel")
		end

		val = [
			(assigned_to.custom_value_for(cf).value rescue nil),
			Setting.plugin_redmine_slack['channel'],
		].find{|v| v.present?}

		# Channel name '-' is reserved for NOT notifying
		return nil if val.to_s == '-'
		val
	end

	def mention_for_user_or_group(assigned_to)
		return nil if assigned_to.blank?

		if assigned_to.class.name == "User"
			cf = UserCustomField.find_by_name("Slack Mention")
		elsif assigned_to.class.name == "Group"
			cf = GroupCustomField.find_by_name("Slack Mention")
		end

		assigned_to.custom_value_for(cf).value rescue nil
	end
	def channel_for_project(proj)
		return nil if proj.blank?

		cf = ProjectCustomField.find_by_name("Slack Channel")

		val = [
			(proj.custom_value_for(cf).value rescue nil),
			(channel_for_project proj.parent),
			Setting.plugin_redmine_slack['channel'],
		].find{|v| v.present?}

		# Channel name '-' is reserved for NOT notifying
		return nil if val.to_s == '-'
		val
	end

	def is_post_updates?(assigned_to)
		return nil if assigned_to.blank?

		if assigned_to.class.name == "User"
			cf = UserCustomField.find_by_name("Slack Post Updates")
		elsif assigned_to.class.name == "Group"
			cf = GroupCustomField.find_by_name("Slack Post Updates")
		end

		val = assigned_to.custom_value_for(cf).value rescue nil
		if val == '1' then true else false end
	end

	def detail_to_field(detail)
		case detail.property
		when "cf"
			custom_field = detail.custom_field
			key = custom_field.name
			title = key
			value = (detail.value)? IssuesController.helpers.format_value(detail.value, custom_field) : ""
		when "attachment"
			key = "attachment"
			title = I18n.t :label_attachment
			value = escape detail.value.to_s
		else
			key = detail.prop_key.to_s.sub("_id", "")
			if key == "parent"
				title = I18n.t "field_#{key}_issue"
			else
				title = I18n.t "field_#{key}"
			end
			value = escape detail.value.to_s
		end

		short = true

		case key
		when "title", "subject", "description"
			short = false
		when "tracker"
			tracker = Tracker.find(detail.value) rescue nil
			value = escape tracker.to_s
		when "project"
			project = Project.find(detail.value) rescue nil
			value = escape project.to_s
		when "status"
			status = IssueStatus.find(detail.value) rescue nil
			value = escape status.to_s
		when "priority"
			priority = IssuePriority.find(detail.value) rescue nil
			value = escape priority.to_s
		when "category"
			category = IssueCategory.find(detail.value) rescue nil
			value = escape category.to_s
		when "assigned_to"
			user = User.find(detail.value) rescue nil
			value = escape user.to_s
		when "fixed_version"
			version = Version.find(detail.value) rescue nil
			value = escape version.to_s
		when "attachment"
			attachment = Attachment.find(detail.prop_key) rescue nil
			value = "<#{object_url attachment}|#{escape attachment.filename}>" if attachment
		when "parent"
			issue = Issue.find(detail.value) rescue nil
			value = "<#{object_url issue}|#{escape issue}>" if issue
		end

		value = "-" if value.empty?

		result = { :title => title, :value => value }
		result[:short] = true if short
		result
	end

	def mentions text
		return nil if text.nil?
		names = extract_usernames text
		names.present? ? "\nTo: " + names.join(', ') : nil
	end

	def extract_usernames text = ''
		if text.nil?
			text = ''
		end

		# slack usernames may only contain lowercase letters, numbers,
		# dashes and underscores and must start with a letter or number.
		text.scan(/@[a-z0-9][a-z0-9_\-]*/).uniq
	end
end
end
