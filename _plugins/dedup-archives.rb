Jekyll::Hooks.register :site, :post_read do |site|
  next unless defined?(Jekyll::Archives) && defined?(Jekyll::Archives::Archive)

  seen = {}
  site.pages.delete_if do |page|
    if page.is_a?(Jekyll::Archives::Archive)
      url = page.url
      if seen[url]
        true
      else
        seen[url] = true
        false
      end
    end
  end
end
