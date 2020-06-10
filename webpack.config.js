const path = require("path");

module.exports = {
	entry: "./src/index.ts",
	module: {
        rules: [
            {
				test: /\.worker\.ts$/,
				use: { loader: "worker-loader" },
			},
			{
				test: /\.ts?$/,
				use: "ts-loader",
				exclude: /node_modules/,
			}
		],
	},
	output: {
		filename: "main.js",
        path: path.resolve(__dirname, "dist"),
        library: 'Wso2OAuth',
        libraryTarget:'umd'
	},
	resolve: {
		extensions: [".tsx", ".ts", ".js"],
	},
};
