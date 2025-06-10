require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  # 1. Metadata for your module
  s.name         = "WdkSecretManager"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]
  s.source       = { :git => package["homepage"], :tag => "#{s.version}" }

  # 2. Platform and Source Files for your module
  s.platforms    = { :ios => "11.0" } # Match or exceed the dependency's version
  s.source_files = "ios/**/*.{h,m,mm}"

  # 3. Standard React Native Dependency
  s.dependency "React-Core"
  s.dependency "sodium-react-native-direct"

end