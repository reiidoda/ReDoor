from pbxproj import XcodeProject

# Path to your Xcode project
project_path = 'RedoorApp/RedoorApp.xcodeproj'

# Load the project
project = XcodeProject.load(f'{project_path}/project.pbxproj')

# 1. Remove the old library
project.remove_files_by_path('../client/target/aarch64-apple-ios-sim/release/libredoor_client.a')

# 2. Add the new xcframework
framework_path = '../client/target/redoor_client.xcframework'
project.add_file(framework_path, parent=project.get_or_create_group('Frameworks'), tree='SOURCE_ROOT')

# 3. Add the framework to the "Embed Frameworks" build phase and set attributes
target = project.get_target_by_name('RedoorApp')
for config in target.buildConfigurationList.buildConfigurations:
    config.buildSettings['FRAMEWORK_SEARCH_PATHS'] = '$(PROJECT_DIR)/../client/target'
    config.buildSettings['OTHER_LDFLAGS'] = '-framework redoor_client'


# 4. Save the project
project.save()

print("Project updated successfully!")
