DEBUG=JEKYLL_GITHUB_TOKEN=blank PAGES_API_URL=http://0.0.0.0
ALIAS=jekyll-rtd-theme

install:
	@gem install jekyll bundler
	@npm install
	@bundle install

format:
	@npm run format

report:
	@npm run report

clean:
	@bundle exec jekyll clean

dist: format clean
	@npm run build

status: format clean checkout
	@git status

theme: dist
	@gem uninstall ${ALIAS}
	@gem build *.gemspec
	@gem install *.gem && rm -f *.gem

build: dist
	@${DEBUG} bundle exec jekyll build --safe --profile

server: dist
	@${DEBUG} bundle exec jekyll server --livereload
