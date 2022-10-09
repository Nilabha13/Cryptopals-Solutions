import web

urls = (
    '/', 'index'
)

class index:
    def GET(self):
        return "Go to <code>/test</code>."

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
