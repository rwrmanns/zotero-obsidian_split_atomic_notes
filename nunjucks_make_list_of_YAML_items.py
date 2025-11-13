"""
Given a list of variable names, the script prints some lines of
a nunjucks template, that assign values to the variables.
The values come from zotero:
https://www.zotero.org/support/kb/item_types_and_fields
"""

# Define the list of variable names:
l_variable_name = ['s_citation_title', 'publicationTitle', 'authors', 'itemType', 'archive', 'archiveLocation', 'uri', 'desktopURI', 'attachment.p_fn']

# Start building the Nunjucks template
template = []
template.append('{% set vars = [')
for i, var in enumerate(l_variable_name):
    comma = ',' if i < len(l_variable_name) - 1 else ''
    template.append(f'  {{ "name": "{var}", "value": {var} }}{comma}')
template.append('] -%}')
template.append('{% if vars | selectattr("value") | list | length > 0 -%}')
               # {% if vars | selectattr("value") | list | length > 0 -%}
template.append('zotero:')
template.append('{% for v in vars %}{% if v.value %}   {{ v.name }}: "{{ v.value }}"{% endif %}')
template.append('{% endfor %}{% endif %}')

# Join everything into a single string
nunjucks_template = "\n".join(template)

# Print result
print(nunjucks_template)

