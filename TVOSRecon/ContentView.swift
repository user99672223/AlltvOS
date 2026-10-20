import SwiftUI

final class ReconViewModel: ObservableObject, ReconEngineDelegate {
    @Published var status: String = "Ready"
    @Published var currentModule: String = ""
    @Published var progress: Double = 0
    @Published var itemCount: Int = 0
    @Published var broadcastAddress: String = "Starting..."
    @Published var isComplete: Bool = false
    @Published var modulesCompleted: Int = 0
    @Published var totalModules: Int = 0

    func start() {
        let engine = ReconEngine.shared
        engine.delegate = self
        totalModules = engine.totalModules

        NetworkServer.shared.start()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            self.broadcastAddress = NetworkServer.shared.displayAddress
            self.status = "Waiting for server..."
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            self.broadcastAddress = NetworkServer.shared.displayAddress
            engine.startRecon()
        }
    }

    func engineDidStart() {
        status = "Collecting..."
        broadcastAddress = NetworkServer.shared.displayAddress
    }

    func engineDidUpdateProgress(moduleName: String, moduleIndex: Int, totalModules: Int) {
        currentModule = moduleName
        modulesCompleted = moduleIndex
        self.totalModules = totalModules
        progress = Double(moduleIndex) / Double(totalModules)
    }

    func engineDidUpdateItemCount(_ count: Int) {
        itemCount = count
    }

    func engineDidFinish(summary: [String: Any]) {
        status = "Complete"
        progress = 1.0
        isComplete = true
        itemCount = summary["total_items"] as? Int ?? itemCount
        currentModule = "Done"
    }
}

struct ContentView: View {
    @StateObject private var viewModel = ReconViewModel()

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            VStack(spacing: 30) {
                Text("TVOSRecon")
                    .font(.system(size: 60, weight: .bold, design: .monospaced))
                    .foregroundColor(.green)

                Text(viewModel.status)
                    .font(.system(size: 36, weight: .medium, design: .monospaced))
                    .foregroundColor(viewModel.isComplete ? Color(red: 0, green: 1, blue: 0.5) : .green)

                if !viewModel.isComplete {
                    VStack(spacing: 12) {
                        Text("Module: \(viewModel.currentModule)")
                            .font(.system(size: 24, design: .monospaced))
                            .foregroundColor(Color(red: 0, green: 0.8, blue: 0))
                            .lineLimit(1)

                        ProgressView(value: viewModel.progress)
                            .progressViewStyle(LinearProgressViewStyle(tint: .green))
                            .frame(width: 600)

                        Text("\(viewModel.modulesCompleted)/\(viewModel.totalModules) modules (\(Int(viewModel.progress * 100))%)")
                            .font(.system(size: 20, design: .monospaced))
                            .foregroundColor(Color(red: 0, green: 0.7, blue: 0))
                    }
                }

                VStack(spacing: 8) {
                    Text("Broadcasting: \(viewModel.broadcastAddress)")
                        .font(.system(size: 22, design: .monospaced))
                        .foregroundColor(Color(red: 0, green: 0.6, blue: 0))

                    Text("Bonjour: _tvosrecon._tcp")
                        .font(.system(size: 20, design: .monospaced))
                        .foregroundColor(Color(red: 0, green: 0.5, blue: 0))

                    Text("Items collected: \(viewModel.itemCount)")
                        .font(.system(size: 22, design: .monospaced))
                        .foregroundColor(Color(red: 0, green: 0.6, blue: 0))
                }

                if viewModel.isComplete {
                    Text("Log saved to app container")
                        .font(.system(size: 18, design: .monospaced))
                        .foregroundColor(Color(red: 0, green: 0.4, blue: 0))
                }
            }
            .padding(60)
        }
        .onAppear {
            viewModel.start()
        }
    }
}
